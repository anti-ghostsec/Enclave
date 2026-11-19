package app.enclave.vault

import android.content.ContentResolver
import android.net.Uri
import android.provider.DocumentsContract
import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import app.enclave.crypto.Kdf
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.DataInputStream
import java.io.EOFException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

/**
 * Portable encrypted backups: one file, protected only by a password you choose, so a vault can
 * be restored on another phone. Unlike the vault itself it doesn't need this phone's hardware key,
 * which also means whoever has the file can try passwords as fast as they like: it's only as
 * strong as its password, so the key derivation is deliberately heavy.
 *
 * The file is a 32-byte salt, an 8-byte nonce prefix, then 1 MiB chunks sealed with AES-256-GCM
 * (nonce = prefix || chunk number; the chunk number and a final-chunk flag are in the AAD, so
 * chunks can't be reordered and the file can't be cut short). Inside: the true length, a manifest
 * (a list of items), the vault's list of files with each file's own key, and every encrypted file
 * and preview byte for byte, then zeros up to a Padmé size. Nothing in the file is readable or
 * recognisable without the password.
 *
 * A backup holds nothing that outlives it. The vault's master key never changes, so it stays out:
 * with it, an old backup and its password would open any later copy of the vault. The vault's
 * settings stay out too, since they list its duress passwords and hold its decoys' keys. All a
 * backup's password opens is the files that were in the vault when it was made. (Backups made by
 * 0.4.0 held both, and can still be restored.)
 */
object Backup {
    val KDF = Kdf.Params(memoryKiB = 128 * 1024, iterations = 4, parallelism = 1)
    private const val SALT = 32
    private const val PREFIX = 8
    private const val CHUNK = 1 shl 20
    private const val TAG = 16
    private val json = Json { ignoreUnknownKeys = true }

    class WrongPassword : IOException("Wrong backup password, or not a backup file")

    @Serializable
    private data class Item(val n: String, val s: Long)

    /** [master] is only in backups made by 0.4.0 (v = 1), whose index is sealed with it. */
    @Serializable
    private data class Manifest(val v: Int, val master: String = "", val created: Long, val items: List<Item>)

    private const val VERSION = 2

    @Serializable
    private data class SavedIndex(val entries: List<Entry> = emptyList())

    // ---- The sealed stream ------------------------------------------------------------------

    private fun nonce(prefix: ByteArray, i: Int) = ByteBuffer.allocate(Aead.NONCE_BYTES).put(prefix).putInt(i).array()
    private fun aad(i: Int, final: Boolean) = ByteBuffer.allocate(5).putInt(i).put(if (final) 1 else 0).array()

    private class SealingStream(private val out: OutputStream, private val key: ByteArray) : OutputStream() {
        private val prefix = Aead.random(PREFIX)
        private val buf = ByteArray(CHUNK)
        private var fill = 0
        private var index = 0
        /** A full chunk held back until we know whether it's the last one. */
        private var held: ByteArray? = null

        fun start(salt: ByteArray) {
            out.write(salt); out.write(prefix)
        }

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            var o = off; var left = len
            while (left > 0) {
                if (fill == CHUNK) {
                    held?.let { seal(it, final = false) }
                    held = buf.copyOf()
                    fill = 0
                }
                val n = minOf(left, CHUNK - fill)
                System.arraycopy(b, o, buf, fill, n)
                fill += n; o += n; left -= n
            }
        }

        private fun seal(plain: ByteArray, final: Boolean) {
            out.write(Aead.raw(Cipher.ENCRYPT_MODE, key, nonce(prefix, index), plain, aad(index, final)))
            plain.fill(0)
            index++
        }

        override fun close() {
            val h = held
            if (h != null && fill == 0) seal(h, final = true)
            else {
                h?.let { seal(it, final = false) }
                seal(buf.copyOf(fill), final = true)
            }
            buf.fill(0)
            key.fill(0)
            out.flush()
        }
    }

    private class OpeningStream(private val input: InputStream, private val key: ByteArray, private val prefix: ByteArray) : InputStream() {
        private var index = 0
        private var current = ByteArray(0)
        private var pos = 0
        private var next: ByteArray? = readSealed()
        private var done = false

        private fun readSealed(): ByteArray? {
            val b = ByteArray(CHUNK + TAG)
            var n = 0
            while (n < b.size) {
                val r = input.read(b, n, b.size - n)
                if (r < 0) break
                n += r
            }
            return if (n == 0) null else b.copyOf(n)
        }

        private fun refill(): Boolean {
            if (done) return false
            val sealed = next ?: throw IOException("the backup file is cut short")
            next = readSealed()
            val final = next == null
            current.fill(0)
            current = try {
                Aead.raw(Cipher.DECRYPT_MODE, key, nonce(prefix, index), sealed, aad(index, final))
            } catch (e: AEADBadTagException) {
                throw if (index == 0) WrongPassword() else IOException("the backup file is damaged")
            }
            index++
            pos = 0
            if (final) done = true
            return true
        }

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (pos == current.size) if (!refill()) return -1
            val n = minOf(len, current.size - pos)
            System.arraycopy(current, pos, b, off, n)
            pos += n
            return n
        }

        override fun close() {
            current.fill(0)
            key.fill(0)
            input.close()
        }
    }

    // ---- Creating a backup ------------------------------------------------------------------

    /**
     * Writes a backup of [store] to [target]. It's written under a temporary name and only
     * renamed once complete, so an interruption leaves no half file.
     */
    fun create(store: VaultStore, password: CharArray, target: File, progress: (Long, Long) -> Unit) =
        write(store, null, password, target, progress)

    /**
     * Writes a backup of [store] into [target], a file just made with Android's file picker. If
     * it fails, the file is deleted again, so no half backup is left where the user put it.
     */
    fun create(store: VaultStore, password: CharArray, cr: ContentResolver, target: Uri, progress: (Long, Long) -> Unit) {
        try {
            val out = cr.openOutputStream(target, "w") ?: throw IOException("couldn't open the backup file")
            val total = out.use {
                val total = writeSealed(store, null, password, it, progress)
                // A file on the phone itself comes as a file descriptor, which can be synced.
                runCatching { (it as? FileOutputStream)?.fd?.sync() }
                total
            }
            progress(total, total)
        } catch (t: Throwable) {
            runCatching { DocumentsContract.deleteDocument(cr, target) }
            throw t
        }
    }

    /**
     * With [oldFormatMaster], writes the file the way 0.4.0 did, master key and settings included.
     * Only the tests use that, to check such backups still restore.
     */
    internal fun write(store: VaultStore, oldFormatMaster: ByteArray?, password: CharArray, target: File, progress: (Long, Long) -> Unit) {
        val tmp = File(target.path + ".tmp")
        try {
            val total = FileOutputStream(tmp).use { fos ->
                writeSealed(store, oldFormatMaster, password, fos, progress).also { fos.fd.sync() }
            }
            if (!tmp.renameTo(target)) throw IOException("couldn't name the backup file")
            progress(total, total)
        } catch (t: Throwable) {
            tmp.delete()
            throw t
        }
    }

    /**
     * Writes the whole sealed backup to [out], from start to end in one pass, and returns its
     * padded size. Doesn't close [out].
     */
    private fun writeSealed(store: VaultStore, oldFormatMaster: ByteArray?, password: CharArray, out: OutputStream, progress: (Long, Long) -> Unit): Long {
        val storage = store.storage
        storage.commit()
        val entries = store.entries.value
        if (entries.isEmpty()) throw IOException("the vault has nothing to back up")
        val old = oldFormatMaster != null
        // The list of files as it is, protected by the backup's own encryption and nothing else.
        val index = if (old) storage.loadIndex()!! else json.encodeToString(SavedIndex(entries)).toByteArray()
        val settings = if (old) storage.loadSettings() else null
        val wanted = entries.filter { !it.folder }.flatMap { listOf(it.id, it.id + ".t") }.toSet()
        val names = storage.names().filter { it in wanted }.sorted()
        val items = buildList {
            add(Item("index", index.size.toLong()))
            settings?.let { add(Item("settings", it.size.toLong())) }
            names.forEach { add(Item(it, storage.size(it))) }
        }
        val manifest = json.encodeToString(
            if (oldFormatMaster != null) Manifest(1, java.util.Base64.getEncoder().encodeToString(oldFormatMaster), System.currentTimeMillis(), items)
            else Manifest(VERSION, created = System.currentTimeMillis(), items = items),
        ).toByteArray()
        val content = 8L + 4 + manifest.size + items.sumOf { it.s }
        val total = ChunkedCipher.padme(content)

        val salt = Aead.random(SALT)
        val key = Kdf.derive(password, null, salt, KDF)
        val sealed = SealingStream(out.buffered(1 shl 20), key)
        sealed.start(salt)
        var written = 0L
        fun put(b: ByteArray, off: Int = 0, len: Int = b.size) {
            sealed.write(b, off, len); written += len
        }
        put(ByteBuffer.allocate(8).putLong(content).array())
        put(ByteBuffer.allocate(4).putInt(manifest.size).array())
        put(manifest)
        manifest.fill(0)
        put(index)
        index.fill(0)
        settings?.let { put(it) }
        val buf = ByteArray(256 * 1024)
        try {
            for (name in names) {
                val size = storage.size(name)
                storage.open(name).use { src ->
                    var p = 0L
                    while (p < size) {
                        val n = src.read(p, buf, 0, minOf(buf.size.toLong(), size - p).toInt())
                        if (n <= 0) throw IOException("$name ended early")
                        put(buf, 0, n)
                        p += n
                    }
                }
                progress(written, total)
            }
        } finally {
            buf.fill(0)
        }
        // Zeros up to the padded size, so the file's size says little about the vault's.
        val zeros = ByteArray(64 * 1024)
        while (written < total) put(zeros, 0, minOf(zeros.size.toLong(), total - written).toInt())
        sealed.close()
        return total
    }

    // ---- Restoring --------------------------------------------------------------------------

    /**
     * A list of entries from a backup, made safe to show: a backup is only as trustworthy as
     * whoever made it. An id is kept once; an entry whose parent isn't a folder in the list, or
     * that is its own ancestor, loses its parent (and so lands in the restore folder). Nothing
     * else is changed, so an honest backup comes through exactly as it was.
     */
    internal fun sound(list: List<Entry>): List<Entry> {
        val ids = HashSet<String>()
        val unique = list.filter { it.id.isNotEmpty() && ids.add(it.id) }
        val folders = unique.filter { it.folder }.associateBy { it.id }
        fun isOwnAncestor(e: Entry): Boolean {
            val seen = HashSet<String>()
            var cur = e.parent
            while (cur != null && seen.add(cur)) {
                if (cur == e.id) return true
                cur = folders[cur]?.parent
            }
            return false
        }
        return unique.map { e ->
            if (e.parent != null && (e.parent !in folders || isOwnAncestor(e))) e.copy(parent = null) else e
        }
    }

    /**
     * Adds everything in the backup at [file] to [store], inside a new folder named [folderName]:
     * files keep their own keys and bytes, and get new ids so nothing collides. Returns the number
     * of files restored. If it fails part-way, nothing is added to the vault's list.
     *
     * [holdsMasterKey] is called for a backup made by 0.4.0, which the user should replace.
     */
    fun restore(
        file: File, password: CharArray, store: VaultStore, folderName: String,
        holdsMasterKey: () -> Unit = {}, progress: (Long, Long) -> Unit,
    ): Int = restore(file.inputStream(), password, store, folderName, holdsMasterKey, progress)

    /** As above, reading the backup from [source] (one picked with Android's file picker), which is closed after. */
    fun restore(
        source: InputStream, password: CharArray, store: VaultStore, folderName: String,
        holdsMasterKey: () -> Unit = {}, progress: (Long, Long) -> Unit,
    ): Int {
        val input = source.buffered(1 shl 20)
        val salt = ByteArray(SALT); val prefix = ByteArray(PREFIX)
        try {
            DataInputStream(input).apply { readFully(salt); readFully(prefix) }
        } catch (_: EOFException) {
            input.close(); throw WrongPassword()
        }
        val key = Kdf.derive(password, null, salt, KDF)
        DataInputStream(OpeningStream(input, key, prefix)).use { data ->
            val content = data.readLong()
            val manifestSize = data.readInt().also { if (it !in 1..(64 shl 20)) throw IOException("the backup file is damaged") }
            val manifestBytes = try {
                ByteArray(manifestSize)
            } catch (_: OutOfMemoryError) {
                throw IOException("the backup file is damaged, or too big for this phone")
            }
            data.readFully(manifestBytes)
            val manifest = json.decodeFromString<Manifest>(String(manifestBytes))
            manifestBytes.fill(0)
            if (manifest.v !in 1..VERSION) throw IOException("this backup was made by a newer version of Enclave")
            if (manifest.v == 1) holdsMasterKey()
            val master = java.util.Base64.getDecoder().decode(manifest.master)
            var read = 8L + 4 + manifestBytes.size
            fun readItem(size: Long): ByteArray {
                val bytes = try {
                    ByteArray(size.toInt())
                } catch (_: OutOfMemoryError) {
                    throw IOException("the backup file is damaged, or too big for this phone")
                }
                data.readFully(bytes); read += size
                return bytes
            }

            var entries: List<Entry> = emptyList()
            val ids = HashMap<String, String>()
            val written = mutableListOf<String>()
            val buf = ByteArray(256 * 1024)
            try {
                for (item in manifest.items) {
                    when (item.n) {
                        "index" -> {
                            if (item.s !in 1..(256L shl 20)) throw IOException("the backup file is damaged")
                            var plain = readItem(item.s)
                            if (manifest.v == 1) {
                                // 0.4.0: the vault's own sealed index, opened with its master key.
                                val indexKey = Aead.subkey(master, "index")
                                plain = Aead.open(indexKey, plain)
                                indexKey.fill(0)
                            }
                            entries = sound(json.decodeFromString<SavedIndex>(String(plain)).entries)
                            plain.fill(0)
                            entries.forEach { ids[it.id] = Aead.hex(Aead.random(16)) }
                        }
                        // Only in 0.4.0's backups. The vault being restored into keeps its own.
                        "settings" -> {
                            if (item.s !in 0..(64L shl 20)) throw IOException("the backup file is damaged")
                            readItem(item.s).fill(0)
                        }
                        else -> {
                            val id = item.n.removeSuffix(".t")
                            val newId = ids[id]
                            if (newId == null) {
                                // A leftover with no file in the index: skip its bytes.
                                var left = item.s
                                while (left > 0) {
                                    val n = data.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                                    if (n < 0) throw IOException("the backup file is cut short")
                                    left -= n; read += n
                                }
                                continue
                            }
                            val newName = if (item.n.endsWith(".t")) "$newId.t" else newId
                            store.storage.put(newName) { out ->
                                var left = item.s
                                while (left > 0) {
                                    val n = data.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                                    if (n < 0) throw IOException("the backup file is cut short")
                                    out.write(buf, 0, n)
                                    left -= n; read += n
                                }
                            }
                            written += newName
                        }
                    }
                    progress(read, content)
                }
            } catch (t: Throwable) {
                // Nothing restored stays behind: the vault's list never pointed at these.
                written.forEach { runCatching { store.storage.delete(it) } }
                throw t
            } finally {
                buf.fill(0)
                master.fill(0)
            }

            val folderId = Aead.hex(Aead.random(16))
            val now = System.currentTimeMillis()
            val restored = entries.mapNotNull { e ->
                val newId = ids.getValue(e.id)
                if (!e.folder && newId !in written) return@mapNotNull null
                e.copy(id = newId, parent = e.parent?.let { ids[it] } ?: folderId)
            }
            store.addRestored(listOf(Entry(folderId, null, folderName, folder = true, added = now)) + restored)
            progress(content, content)
            return restored.count { !it.folder }
        }
    }
}
