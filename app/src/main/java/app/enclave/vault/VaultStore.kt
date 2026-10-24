package app.enclave.vault

import android.content.ContentResolver
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import android.webkit.MimeTypeMap
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Base64
import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.DigestInputStream
import java.security.MessageDigest
import java.io.File
import java.io.InputStream
import java.io.OutputStream

@Serializable
data class Entry(
    val id: String,
    val parent: String? = null,
    val name: String,
    val folder: Boolean = false,
    val size: Long = 0,
    val mime: String = "application/octet-stream",
    val added: Long = 0,
    val key: String = "",
)

@Serializable
data class DuressSlot(val slot: Int, val action: String, val label: String, val dir: String? = null)

@Serializable
data class VaultSettings(
    val duress: List<DuressSlot> = emptyList(),
    val usesKeyfile: Boolean = false,
    /** "name", "date", "size" or "type". */
    val sort: String = "name",
    val sortDescending: Boolean = false,
    val grid: Boolean = true,
    /** How to open each kind of file: "enclave" (built-in viewer), "ask", or an app's package name. */
    val openVideos: String = "enclave",
    val openAudio: String = "enclave",
    val openOther: String = "ask",
    val swipeVertical: Boolean = false,
    val slideshowSeconds: Int = 4,
    /** Apps offered when sharing (as "package/activity"). Empty = every app that can receive files. */
    val shareApps: List<String> = emptyList(),
    /** Show what's being sent and to which app, and ask before sending. */
    val confirmShare: Boolean = true,
)

@Serializable
private data class Index(val entries: List<Entry> = emptyList())

/**
 * One unlocked vault: an encrypted index (names, folders, per-file keys) plus encrypted blobs.
 *
 * What someone who copies the vault's raw files can still learn is kept to a minimum:
 * - blobs are padded (Padmé), so sizes can't be matched to known originals;
 * - every file has a preview file of one fixed size, so previews don't reveal which are media;
 * - every file's modified time is set to the same fixed date, hiding when things were added.
 */
class VaultStore(val dir: File, master: ByteArray) {
    private val indexKey = Aead.subkey(master, "index")
    private val settingsKey = Aead.subkey(master, "settings")
    private val json = Json { ignoreUnknownKeys = true }

    private val indexFile = File(dir, "index.enc")
    private val settingsFile = File(dir, "settings.enc")

    private val _entries = MutableStateFlow<List<Entry>>(emptyList())
    val entries: StateFlow<List<Entry>> = _entries
    private val _settings = MutableStateFlow(VaultSettings())
    val settings: StateFlow<VaultSettings> = _settings

    /** (done, total) while older files are being upgraded to the current format, else null. */
    private val _upgrade = MutableStateFlow<Pair<Int, Int>?>(null)
    val upgrade: StateFlow<Pair<Int, Int>?> = _upgrade

    @Volatile private var closed = false

    init {
        dir.mkdirs()
        if (indexFile.exists()) {
            _entries.value = json.decodeFromString<Index>(String(Aead.open(indexKey, indexFile.readBytes()))).entries
        }
        if (settingsFile.exists()) {
            _settings.value = json.decodeFromString(String(Aead.open(settingsKey, settingsFile.readBytes())))
        }
        removeLeftovers()
    }

    /**
     * Deletes half-written files and blobs the index no longer points to (e.g. after a crash
     * mid-import or mid-upgrade). Runs before the vault is shown, so nothing is in progress.
     */
    private fun removeLeftovers() {
        val live = _entries.value.filter { !it.folder }.map { it.id }.toSet()
        dir.listFiles()?.forEach { f ->
            val n = f.name
            val id = n.removeSuffix(".tmp").removeSuffix(".t")
            when {
                n.endsWith(".tmp") -> f.delete()
                id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' } && id !in live -> f.delete()
            }
        }
    }

    private fun stamp(f: File) {
        f.setLastModified(FIXED_TIME)
        dir.setLastModified(FIXED_TIME)
    }

    private fun atomicWrite(f: File, bytes: ByteArray) {
        val tmp = File(f.path + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(f)) {
            f.delete(); tmp.renameTo(f)
        }
        stamp(f)
    }

    /**
     * The only way the index changes. Synchronized with [close], so nothing can ever be written
     * with wiped keys or from an emptied list.
     */
    @Synchronized
    private fun updateEntries(change: (List<Entry>) -> List<Entry>): Boolean {
        if (closed) return false
        val before = _entries.value
        val after = change(before)
        if (after == before) return false
        atomicWrite(indexFile, Aead.seal(indexKey, json.encodeToString(Index(after)).toByteArray()))
        _entries.value = after
        return true
    }

    @Synchronized
    fun updateSettings(f: (VaultSettings) -> VaultSettings) {
        if (closed) return
        val s = f(_settings.value)
        atomicWrite(settingsFile, Aead.seal(settingsKey, json.encodeToString(s).toByteArray()))
        _settings.value = s
    }

    private fun newId() = Aead.hex(Aead.random(16))
    private fun blob(id: String) = File(dir, id)
    private fun blob(e: Entry) = blob(e.id)
    private fun keyOf(e: Entry) = Base64.decode(e.key, Base64.NO_WRAP)

    fun children(parent: String?) = _entries.value.filter { it.parent == parent }

    fun createFolder(name: String, parent: String?) {
        updateEntries { it + Entry(newId(), parent, name, folder = true, added = System.currentTimeMillis()) }
    }

    /** Encrypts a file picked by the user into the vault. Plaintext never touches our storage. */
    fun import(cr: ContentResolver, uri: Uri, parent: String?): Entry {
        var name = "file"
        cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst() && !it.isNull(0)) name = it.getString(0)
        }
        return importStream(name, cr.getType(uri) ?: mimeOf(name), parent) { cr.openInputStream(uri)!! }
    }

    fun importFile(f: File, parent: String?): Entry = importStream(f.name, mimeOf(f.name), parent) { f.inputStream() }

    private fun mimeOf(name: String) =
        MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase()) ?: "application/octet-stream"

    /** Encrypts into a new blob + placeholder preview. Returns (size, key) once both are in place. */
    private fun writeBlob(id: String, key: ByteArray, open: () -> InputStream): Long {
        val tmp = File(dir, "$id.tmp")
        val size = try {
            open().use { input -> tmp.outputStream().buffered().use { out -> ChunkedCipher.encrypt(key, input, out) } }
        } catch (t: Throwable) {
            tmp.delete(); throw t
        }
        val f = blob(id)
        tmp.renameTo(f)
        stamp(f)
        return size
    }

    private fun importStream(name: String, mime: String, parent: String?, open: () -> InputStream): Entry {
        check(!closed) { "vault is locked" }
        val id = newId()
        val key = Aead.random(Aead.KEY_BYTES)
        val size = writeBlob(id, key, open)
        writeThumb(id, key, null, THUMB_PENDING)
        val e = Entry(id, parent, name, false, size, mime, System.currentTimeMillis(), Base64.encodeToString(key, Base64.NO_WRAP))
        key.fill(0)
        if (!updateEntries { it + e }) {
            blob(id).delete(); thumbFile(id).delete()
            error("vault is locked")
        }
        return e
    }

    fun reader(e: Entry) = ChunkedCipher.Reader(blob(e), keyOf(e), e.size)

    fun blobOf(e: Entry) = blob(e)

    /** A copy of one file's key, for [Shares]. */
    fun keyBytes(e: Entry) = keyOf(e)

    // ---- Previews -------------------------------------------------------------------------

    private fun thumbFile(id: String) = File(dir, "$id.t")
    private val thumbs = object : LruCache<String, Bitmap>(24 * 1024 * 1024) {
        override fun sizeOf(k: String, v: Bitmap) = v.byteCount
    }

    /**
     * Every file gets a preview file of exactly the same size: [THUMB_BYTES] of plaintext holding a
     * 4-byte state/length, the JPEG (if any) and random filler, sealed with a key derived from
     * that file's own key.
     */
    private fun writeThumb(id: String, fileKey: ByteArray, jpgIn: ByteArray?, state: Int) {
        val jpg = jpgIn?.takeIf { it.size <= THUMB_BYTES - 4 }
        val body = Aead.random(THUMB_BYTES)
        val len = jpg?.size ?: state
        ByteBuffer.wrap(body).putInt(len)
        jpg?.copyInto(body, 4)
        val k = Aead.subkey(fileKey, "thumbnail")
        atomicWrite(thumbFile(id), Aead.seal(k, body))
        k.fill(0); body.fill(0)
    }

    /** The JPEG inside a preview file (current or old format), or null if there's none yet. */
    private fun readThumbJpg(id: String, fileKey: ByteArray): ByteArray? {
        val f = thumbFile(id)
        if (!f.exists()) return null
        val k = Aead.subkey(fileKey, "thumbnail")
        val body = runCatching { Aead.open(k, f.readBytes()) }.getOrNull()
        k.fill(0)
        if (body == null) return null
        if (body.size != THUMB_BYTES) return body // first version: the sealed JPEG itself
        val len = ByteBuffer.wrap(body).int
        return if (len > 0 && len <= THUMB_BYTES - 4) body.copyOfRange(4, 4 + len) else null
    }

    private fun thumbState(id: String, fileKey: ByteArray): Int? {
        val f = thumbFile(id)
        if (!f.exists() || f.length() != SEALED_THUMB_BYTES) return null
        val k = Aead.subkey(fileKey, "thumbnail")
        val body = runCatching { Aead.open(k, f.readBytes()) }.getOrNull()
        k.fill(0)
        return body?.let { ByteBuffer.wrap(it).int }
    }

    private fun jpegOf(b: Bitmap): ByteArray? {
        for (q in intArrayOf(80, 65, 50, 35)) {
            val bytes = ByteArrayOutputStream().also { b.compress(Bitmap.CompressFormat.JPEG, q, it) }.toByteArray()
            if (bytes.size <= THUMB_BYTES - 4) return bytes
        }
        return null
    }

    /**
     * A small preview for images and videos. Made once, then stored encrypted (see [writeThumb]);
     * decrypted previews only ever live in memory.
     */
    fun thumbnail(e: Entry): Bitmap? {
        if (!Media.isImage(e) && !Media.isVideo(e)) return null
        thumbs.get(e.id)?.let { return it }
        val key = keyOf(e)
        try {
            val state = thumbState(e.id, key)
            if (state == THUMB_NONE) return null
            if (state != null && state > 0) {
                val jpg = readThumbJpg(e.id, key) ?: return null
                return BitmapFactory.decodeByteArray(jpg, 0, jpg.size).also { jpg.fill(0); it?.let { b -> thumbs.put(e.id, b) } }
            }
            if (closed) return null
            val bmp = runCatching { Media.makeThumbnail(this, e) }.getOrNull()
            val jpg = bmp?.let(::jpegOf)
            if (!closed && _entries.value.any { it.id == e.id }) writeThumb(e.id, key, jpg, if (jpg == null) THUMB_NONE else THUMB_PENDING)
            jpg?.fill(0)
            bmp?.let { thumbs.put(e.id, it) }
            return bmp
        } finally {
            key.fill(0)
        }
    }

    // ---- Upgrading older files ------------------------------------------------------------

    /**
     * Brings files from older versions up to date: re-encrypts unpadded blobs with padding and
     * gives every file a fixed-size preview. Each file is re-encrypted under a new id and key,
     * checked to decrypt to exactly the same bytes, and only then swapped in by one index update;
     * the old blob is deleted last. An interruption at any point leaves the old file intact.
     */
    fun upgradeOldFiles() {
        val todo = _entries.value.filter { !it.folder && needsUpgrade(it) }
        if (todo.isEmpty()) return
        _upgrade.value = 0 to todo.size
        try {
            todo.forEachIndexed { i, e ->
                if (closed) return
                runCatching { upgrade(e) }
                _upgrade.value = (i + 1) to todo.size
            }
        } finally {
            _upgrade.value = null
        }
    }

    private fun needsUpgrade(e: Entry): Boolean {
        if (ChunkedCipher.versionOf(blob(e)) == ChunkedCipher.VERSION_PLAIN.toInt()) return true
        if (!dir.resolve(e.id).exists()) return false
        val t = thumbFile(e.id)
        return !t.exists() || t.length() != SEALED_THUMB_BYTES || blob(e).lastModified() != FIXED_TIME
    }

    private fun upgrade(e: Entry) {
        val oldKey = keyOf(e)
        try {
            if (ChunkedCipher.versionOf(blob(e)) != ChunkedCipher.VERSION_PLAIN.toInt()) {
                // Already padded: just fix the preview file and the timestamp.
                if (thumbState(e.id, oldKey) == null) {
                    val jpg = readThumbJpg(e.id, oldKey)
                    if (!closed) writeThumb(e.id, oldKey, jpg, THUMB_PENDING)
                }
                stamp(blob(e))
                return
            }
            val newId = newId()
            val newKey = Aead.random(Aead.KEY_BYTES)
            try {
                val before = MessageDigest.getInstance("SHA-256")
                val size = reader(e).use { old -> writeBlob(newId, newKey) { DigestInputStream(old.inputStream(), before) } }
                val after = MessageDigest.getInstance("SHA-256")
                ChunkedCipher.Reader(blob(newId), newKey, size).use { r ->
                    val buf = ByteArray(64 * 1024)
                    DigestInputStream(r.inputStream(), after).use { while (it.read(buf) >= 0) Unit }
                }
                if (size != e.size || !MessageDigest.isEqual(before.digest(), after.digest())) error("verification failed")
                writeThumb(newId, newKey, readThumbJpg(e.id, oldKey), THUMB_PENDING)
                val newKeyText = Base64.encodeToString(newKey, Base64.NO_WRAP)
                val swapped = updateEntries { list ->
                    list.map { if (it.id == e.id) it.copy(id = newId, key = newKeyText) else it }
                }
                if (swapped) {
                    blob(e).delete(); thumbFile(e.id).delete(); thumbs.remove(e.id)
                } else {
                    // Deleted (or vault locked) meanwhile: keep things exactly as they were.
                    blob(newId).delete(); thumbFile(newId).delete()
                }
            } catch (t: Throwable) {
                blob(newId).delete(); thumbFile(newId).delete()
                throw t
            } finally {
                newKey.fill(0)
            }
        } finally {
            oldKey.fill(0)
        }
    }

    // ---- Everyday operations ----------------------------------------------------------------

    fun export(e: Entry, out: OutputStream) {
        reader(e).use { r -> r.inputStream().copyTo(out) }
    }

    /** Writes decrypted copies of [ids] (folders recursively) into [target]. Returns the file count. */
    fun exportTo(ids: Collection<String>, target: File, freeName: (File, String) -> File): Int {
        var count = 0
        fun write(e: Entry, into: File) {
            if (e.folder) {
                val d = freeName(into, e.name).also { it.mkdirs() }
                _entries.value.filter { it.parent == e.id }.forEach { write(it, d) }
            } else {
                freeName(into, e.name).outputStream().use { export(e, it) }
                count++
            }
        }
        _entries.value.filter { it.id in ids }.forEach { write(it, target) }
        return count
    }

    fun rename(e: Entry, name: String) {
        updateEntries { list -> list.map { if (it.id == e.id) it.copy(name = name) else it } }
    }

    /** True if [id] is [ancestor] or lives somewhere inside it. */
    fun isWithin(id: String?, ancestor: String): Boolean {
        var cur = id
        while (cur != null) {
            if (cur == ancestor) return true
            cur = _entries.value.firstOrNull { it.id == cur }?.parent
        }
        return false
    }

    /** Moves entries into [parent] (null = vault root). Folders can't be moved into themselves. */
    fun move(ids: Collection<String>, parent: String?) {
        val movable = ids.filter { parent == null || !isWithin(parent, it) }.toSet()
        updateEntries { list -> list.map { if (it.id in movable) it.copy(parent = parent) else it } }
    }

    fun pathOf(e: Entry): String {
        val parts = mutableListOf(e.name)
        var cur = e.parent
        while (cur != null) {
            val p = _entries.value.firstOrNull { it.id == cur } ?: break
            parts.add(0, p.name); cur = p.parent
        }
        return parts.joinToString(" / ")
    }

    fun delete(e: Entry) = delete(listOf(e.id))

    fun delete(ids: Collection<String>) {
        val all = _entries.value
        val doomed = mutableSetOf<String>()
        fun collect(id: String) {
            if (!doomed.add(id)) return
            all.filter { it.parent == id }.forEach { collect(it.id) }
        }
        ids.forEach(::collect)
        val files = all.filter { it.id in doomed && !it.folder }
        if (updateEntries { list -> list.filter { it.id !in doomed } }) {
            files.forEach { blob(it).delete(); thumbFile(it.id).delete(); thumbs.remove(it.id) }
        }
    }

    /**
     * Groups of files with identical contents. Only files of the same size are compared, by a
     * SHA-256 of their decrypted contents, so it reads as little as possible. Nothing is deleted.
     */
    fun findDuplicates(progress: (done: Int, total: Int) -> Unit): List<List<Entry>> {
        val candidates = _entries.value.filter { !it.folder }.groupBy { it.size }.values.filter { it.size > 1 }.flatten()
        val byHash = HashMap<String, MutableList<Entry>>()
        val buf = ByteArray(64 * 1024)
        candidates.forEachIndexed { i, e ->
            if (closed) return emptyList()
            runCatching {
                val md = MessageDigest.getInstance("SHA-256")
                reader(e).use { r -> r.inputStream().use { input -> while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) } } }
                byHash.getOrPut("${e.size}:${Aead.hex(md.digest())}") { mutableListOf() } += e
            }
            progress(i + 1, candidates.size)
        }
        buf.fill(0)
        return byHash.values.filter { it.size > 1 }
            .map { g -> g.sortedBy { it.added } }
            .sortedByDescending { it.first().size * (it.size - 1) }
    }

    @Synchronized
    fun close() {
        closed = true
        indexKey.fill(0); settingsKey.fill(0)
        thumbs.evictAll()
        _entries.value = emptyList()
    }

    companion object {
        /** 1 January 2020: the modified time every vault file is given. */
        const val FIXED_TIME = 1_577_836_800_000L
        const val THUMB_BYTES = 48 * 1024
        const val SEALED_THUMB_BYTES = (Aead.NONCE_BYTES + THUMB_BYTES + Aead.TAG_BYTES).toLong()
        private const val THUMB_PENDING = 0
        private const val THUMB_NONE = -1
    }
}
