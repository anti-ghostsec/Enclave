package app.enclave.vault

import app.enclave.crypto.BlobSource
import app.enclave.crypto.FileBlob
import java.io.File
import java.io.IOException
import java.io.OutputStream

/**
 * Where a vault keeps its bytes. The vault's own encryption sits on top: the index and settings
 * arrive here already sealed, and every blob is an encrypted file or preview. Blobs are named by
 * the vault ("<id>" for a file, "<id>.t" for its preview).
 */
interface Storage : java.io.Closeable {
    /** True when nothing may be written (a decoy opened on its own). */
    val readOnly: Boolean

    fun loadIndex(): ByteArray?
    fun loadSettings(): ByteArray?

    /** Saves the sealed index together with every blob change so far. Durable on return. */
    fun saveIndex(sealed: ByteArray)
    fun saveSettings(sealed: ByteArray)

    fun names(): Set<String>
    fun has(name: String): Boolean = size(name) >= 0

    /** The blob's length, or -1 if there's no such blob. */
    fun size(name: String): Long
    fun open(name: String): BlobSource

    /** Writes a blob (replacing any of the same name). Durable at the next [commit] or [saveIndex]. */
    fun put(name: String, write: (OutputStream) -> Unit)
    fun delete(name: String)

    /** Makes every change so far durable. */
    fun commit()
}

/** Thrown for any write to a read-only vault. Worded like an ordinary full-storage error. */
class StorageFullException : IOException("Storage is full")

/**
 * The original format: one directory per vault, a file per blob. Still used for vaults that
 * haven't moved into a container yet (and for old decoys), so older vaults keep opening.
 */
class DirStorage(val dir: File) : Storage {
    override val readOnly = false
    private val indexFile = File(dir, "index.enc")
    private val settingsFile = File(dir, "settings.enc")

    // The directory is made when something is first written, never just by looking: a directory
    // named after a vault's key, left behind by every unlock, showed how many vaults there are.

    fun file(name: String) = File(dir, name)

    /** Every vault file's modified time is the same fixed date, hiding when things were added. */
    fun stamp(f: File) {
        f.setLastModified(VaultStore.FIXED_TIME)
        dir.setLastModified(VaultStore.FIXED_TIME)
    }

    private fun atomicWrite(f: File, write: (OutputStream) -> Unit) {
        val tmp = File(f.path + ".tmp")
        dir.mkdirs()
        try {
            tmp.outputStream().buffered().use(write)
        } catch (t: Throwable) {
            tmp.delete(); throw t
        }
        if (!tmp.renameTo(f)) {
            f.delete(); tmp.renameTo(f)
        }
        stamp(f)
    }

    val hasVault get() = indexFile.exists()

    override fun loadIndex(): ByteArray? = indexFile.takeIf { it.exists() }?.readBytes()
    override fun loadSettings(): ByteArray? = settingsFile.takeIf { it.exists() }?.readBytes()
    override fun saveIndex(sealed: ByteArray) = atomicWrite(indexFile) { it.write(sealed) }
    override fun saveSettings(sealed: ByteArray) = atomicWrite(settingsFile) { it.write(sealed) }

    override fun names(): Set<String> = dir.listFiles().orEmpty().map { it.name }
        .filter { n -> n.removeSuffix(".t").let { id -> id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' } } }
        .toSet()

    override fun size(name: String): Long = file(name).let { if (it.exists()) it.length() else -1 }
    override fun open(name: String): BlobSource = FileBlob(file(name))
    override fun put(name: String, write: (OutputStream) -> Unit) = atomicWrite(file(name), write)
    override fun delete(name: String) {
        file(name).delete()
    }

    override fun commit() {}
    override fun close() {}

    /** Deletes half-written files left by a crash. */
    fun removeTemporaryFiles() {
        dir.listFiles()?.filter { it.name.endsWith(".tmp") }?.forEach { it.delete() }
    }

    /** Removes the whole directory, once its contents live somewhere else. */
    fun deleteAll() = dir.deleteRecursively()
}

/** An empty vault that can't be written: what a decoy with nothing in it shows. */
class EmptyStorage : Storage {
    override val readOnly = true
    override fun loadIndex(): ByteArray? = null
    override fun loadSettings(): ByteArray? = null
    override fun saveIndex(sealed: ByteArray) = throw StorageFullException()
    override fun saveSettings(sealed: ByteArray) {}
    override fun names(): Set<String> = emptySet()
    override fun size(name: String): Long = -1
    override fun open(name: String): BlobSource = throw IOException("no such file")
    override fun put(name: String, write: (OutputStream) -> Unit) = throw StorageFullException()
    override fun delete(name: String) = throw StorageFullException()
    override fun commit() {}
    override fun close() {}
}

/**
 * A vault that appears fully writable but keeps every change for this session only. Used for a
 * decoy opened on its own: adding, renaming and deleting all work as anyone checking would
 * expect, yet nothing is written to the containers, where it could land on the hidden real
 * vault's blocks. Everything changed is forgotten when the vault locks.
 *
 * Small blobs stay in memory. Bigger ones go to files in [scratch], so there's room for as much
 * as a vault in the containers would take, not just what fits in memory. Those files hold only
 * what the containers would: blobs already encrypted with keys that exist in memory alone. They
 * are deleted when the vault locks, and whatever a crash leaves behind is unreadable and removed
 * when Enclave next starts. Without [scratch], everything stays in memory, up to [MEMORY_ONLY_LIMIT].
 */
class SessionOnlyStorage(private val base: Storage, private val scratch: File? = null) : Storage {
    override val readOnly = false

    private class Blob(val bytes: ByteArray?, val file: File?) {
        val size: Long get() = bytes?.size?.toLong() ?: file!!.length()
        fun discard() {
            bytes?.fill(0)
            file?.let { it.delete(); it.parentFile?.setLastModified(VaultStore.FIXED_TIME) }
        }
    }

    private val added = HashMap<String, Blob>()
    private val removed = HashSet<String>()
    private var index: ByteArray? = null
    private var settings: ByteArray? = null
    /** Bytes of blobs held in memory. */
    private var inMemory = 0L
    private var files = 0L

    override fun loadIndex(): ByteArray? = synchronized(this) { index?.copyOf() } ?: base.loadIndex()
    override fun loadSettings(): ByteArray? = synchronized(this) { settings?.copyOf() } ?: base.loadSettings()

    @Synchronized
    override fun saveIndex(sealed: ByteArray) {
        index = sealed.copyOf()
    }

    @Synchronized
    override fun saveSettings(sealed: ByteArray) {
        settings = sealed.copyOf()
    }

    @Synchronized
    override fun names(): Set<String> = base.names() - removed + added.keys

    @Synchronized
    override fun size(name: String): Long = added[name]?.size ?: if (name in removed) -1 else base.size(name)

    override fun open(name: String): BlobSource {
        synchronized(this) {
            added[name]?.let { b -> return b.bytes?.let { app.enclave.crypto.BytesBlob(it) } ?: app.enclave.crypto.FileBlob(b.file!!) }
            if (name in removed) throw IOException("no such file")
        }
        return base.open(name)
    }

    /** Collects a blob in memory, moving it to a file once it's too big to keep there. */
    private inner class Collector : OutputStream() {
        private var mem: java.io.ByteArrayOutputStream? = java.io.ByteArrayOutputStream()
        private var file: File? = null
        private var out: OutputStream? = null

        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            val m = mem
            if (m != null) {
                val held = synchronized(this@SessionOnlyStorage) { inMemory }
                if (m.size() + len <= IN_MEMORY_BLOB && held + m.size() + len <= IN_MEMORY_TOTAL) return m.write(b, off, len)
                if (scratch == null) {
                    if (held + m.size() + len > MEMORY_ONLY_LIMIT) throw StorageFullException()
                    return m.write(b, off, len)
                }
                spill(m)
            }
            try {
                out!!.write(b, off, len)
            } catch (e: IOException) {
                // The phone's storage ran out, as it would for a vault adding a container.
                throw StorageFullException()
            }
        }

        private fun spill(m: java.io.ByteArrayOutputStream) {
            try {
                scratch!!.mkdirs()
                val f = File(scratch, synchronized(this@SessionOnlyStorage) { files++ }.toString())
                stampScratch()
                file = f
                val o = f.outputStream().buffered(256 * 1024)
                out = o
                m.writeTo(o)
            } catch (e: IOException) {
                throw StorageFullException()
            }
            mem = null
        }

        fun finish(): Blob {
            try {
                out?.close()
            } catch (e: IOException) {
                throw StorageFullException()
            }
            // Like everything else here, it says nothing about when it was written.
            file?.setLastModified(VaultStore.FIXED_TIME)
            return Blob(mem?.toByteArray(), file)
        }

        fun abandon() {
            runCatching { out?.close() }
            file?.delete()
        }
    }

    override fun put(name: String, write: (OutputStream) -> Unit) {
        val c = Collector()
        val blob = try {
            write(c)
            c.finish()
        } catch (t: Throwable) {
            c.abandon()
            throw t
        }
        synchronized(this) {
            added.put(name, blob)?.let { forget(it) }
            blob.bytes?.let { inMemory += it.size }
            removed += name
        }
    }

    private fun forget(b: Blob) {
        b.bytes?.let { inMemory -= it.size }
        b.discard()
    }

    @Synchronized
    override fun delete(name: String) {
        added.remove(name)?.let { forget(it) }
        removed += name
    }

    override fun commit() {}

    private fun stampScratch() { scratch?.setLastModified(VaultStore.FIXED_TIME) }

    @Synchronized
    override fun close() {
        added.values.forEach { it.discard() }
        added.clear()
        inMemory = 0
        // The folder stays, empty: it is there whichever vault is open.
        scratch?.listFiles()?.forEach { it.deleteRecursively() }
        stampScratch()
        index?.fill(0); settings?.fill(0)
        base.close()
    }

    private companion object {
        /** A blob up to this size is kept in memory (every preview is smaller). */
        const val IN_MEMORY_BLOB = 256 * 1024
        /** Memory the small blobs may use before they go to files too. */
        const val IN_MEMORY_TOTAL = 32L * 1024 * 1024
        /** With nowhere to put files: memory this may use before it says storage is full. */
        const val MEMORY_ONLY_LIMIT = 192L * 1024 * 1024
    }
}
