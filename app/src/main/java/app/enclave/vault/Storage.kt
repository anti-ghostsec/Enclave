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

    init {
        dir.mkdirs()
    }

    fun file(name: String) = File(dir, name)

    /** Every vault file's modified time is the same fixed date, hiding when things were added. */
    fun stamp(f: File) {
        f.setLastModified(VaultStore.FIXED_TIME)
        dir.setLastModified(VaultStore.FIXED_TIME)
    }

    private fun atomicWrite(f: File, write: (OutputStream) -> Unit) {
        val tmp = File(f.path + ".tmp")
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
 * A vault that appears fully writable but keeps every change in memory for this session only.
 * Used for a decoy opened on its own: adding, renaming and deleting all work as anyone checking
 * would expect, yet nothing is written to the containers, where it could land on the hidden real
 * vault's blocks. Everything changed is forgotten when the vault locks.
 */
class SessionOnlyStorage(private val base: Storage) : Storage {
    override val readOnly = false
    private val added = HashMap<String, ByteArray>()
    private val removed = HashSet<String>()
    private var index: ByteArray? = null
    private var settings: ByteArray? = null
    private var bytes = 0L

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
    override fun size(name: String): Long = added[name]?.size?.toLong() ?: if (name in removed) -1 else base.size(name)

    override fun open(name: String): BlobSource {
        synchronized(this) {
            added[name]?.let { return app.enclave.crypto.BytesBlob(it) }
            if (name in removed) throw IOException("no such file")
        }
        return base.open(name)
    }

    override fun put(name: String, write: (OutputStream) -> Unit) {
        val out = object : java.io.ByteArrayOutputStream() {
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (synchronized(this@SessionOnlyStorage) { bytes } + count + len > LIMIT) throw StorageFullException()
                super.write(b, off, len)
            }
        }
        write(out)
        synchronized(this) {
            added.put(name, out.toByteArray())?.let { bytes -= it.size }
            bytes += out.size()
            removed += name
        }
    }

    @Synchronized
    override fun delete(name: String) {
        added.remove(name)?.let { it.fill(0); bytes -= it.size }
        removed += name
    }

    override fun commit() {}

    @Synchronized
    override fun close() {
        added.values.forEach { it.fill(0) }
        added.clear()
        index?.fill(0); settings?.fill(0)
        base.close()
    }

    private companion object {
        /** Memory this may use before it says storage is full. */
        const val LIMIT = 192L * 1024 * 1024
    }
}
