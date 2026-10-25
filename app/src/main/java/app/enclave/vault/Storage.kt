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
