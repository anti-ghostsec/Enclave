package app.enclave.vault

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
 * (the vault's master key and a list of items), the vault's sealed index and settings, and every
 * encrypted file and preview byte for byte, then zeros up to a Padmé size. Nothing in the file
 * is readable or recognisable without the password.
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

    @Serializable
    private data class Manifest(val v: Int, val master: String, val created: Long, val items: List<Item>)

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
     * Writes a backup of [store] (whose master key is [master]) to [target]. It's written under a
     * temporary name and only renamed once complete, so an interruption leaves no half file.
     */
    fun create(store: VaultStore, master: ByteArray, password: CharArray, target: File, progress: (Long, Long) -> Unit) {
        val storage = store.storage
        storage.commit()
        val index = storage.loadIndex() ?: throw IOException("the vault has nothing to back up")
        val settings = storage.loadSettings()
        val names = storage.names().sorted()
        val items = buildList {
            add(Item("index", index.size.toLong()))
            settings?.let { add(Item("settings", it.size.toLong())) }
            names.forEach { add(Item(it, storage.size(it))) }
        }
        val manifest = json.encodeToString(
            Manifest(1, java.util.Base64.getEncoder().encodeToString(master), System.currentTimeMillis(), items),
        ).toByteArray()
        val content = 8L + 4 + manifest.size + items.sumOf { it.s }
        val total = ChunkedCipher.padme(content)

        val salt = Aead.random(SALT)
        val key = Kdf.derive(password, null, salt, KDF)
        val tmp = File(target.path + ".tmp")
        try {
            FileOutputStream(tmp).use { fos ->
                val sealed = SealingStream(fos.buffered(1 shl 20), key)
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
                fos.fd.sync()
            }
            if (!tmp.renameTo(target)) throw IOException("couldn't name the backup file")
            progress(total, total)
        } catch (t: Throwable) {
            tmp.delete()
            throw t
        }
    }

    // ---- Restoring --------------------------------------------------------------------------

    /**
     * Adds everything in the backup at [file] to [store], inside a new folder named [folderName]:
     * files keep their own keys and bytes, and get new ids so nothing collides. Returns the number
     * of files restored. If it fails part-way, nothing is added to the vault's list.
     */
    fun restore(file: File, password: CharArray, store: VaultStore, folderName: String, progress: (Long, Long) -> Unit): Int {
        val input = file.inputStream().buffered(1 shl 20)
        val salt = ByteArray(SALT); val prefix = ByteArray(PREFIX)
        try {
            DataInputStream(input).apply { readFully(salt); readFully(prefix) }
        } catch (_: EOFException) {
            input.close(); throw WrongPassword()
        }
        val key = Kdf.derive(password, null, salt, KDF)
        DataInputStream(OpeningStream(input, key, prefix)).use { data ->
            val content = data.readLong()
            val manifestBytes = ByteArray(data.readInt().also { if (it !in 1..(64 shl 20)) throw IOException("the backup file is damaged") })
            data.readFully(manifestBytes)
            val manifest = json.decodeFromString<Manifest>(String(manifestBytes))
            manifestBytes.fill(0)
            val master = java.util.Base64.getDecoder().decode(manifest.master)
            var read = 8L + 4 + manifestBytes.size
            fun readItem(size: Long): ByteArray = ByteArray(size.toInt()).also { data.readFully(it); read += size }

            var entries: List<Entry> = emptyList()
            val ids = HashMap<String, String>()
            val written = mutableListOf<String>()
            val buf = ByteArray(256 * 1024)
            try {
                for (item in manifest.items) {
                    when (item.n) {
                        "index" -> {
                            val sealed = readItem(item.s)
                            val indexKey = Aead.subkey(master, "index")
                            entries = json.decodeFromString<SavedIndex>(String(Aead.open(indexKey, sealed))).entries
                            indexKey.fill(0)
                            entries.forEach { ids[it.id] = Aead.hex(Aead.random(16)) }
                        }
                        "settings" -> readItem(item.s).fill(0) // the vault being restored into keeps its own
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
