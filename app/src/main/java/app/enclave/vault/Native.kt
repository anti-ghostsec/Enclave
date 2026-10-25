package app.enclave.vault

/**
 * The deniable storage crate (native/deniable), through Enclave's bridge (native/enclave-jni).
 * Containers are handles; volumes are small numbers within a container. Errors are IOExceptions,
 * and a full container's message is [FULL].
 */
object Native {
    const val FULL = "container full"

    init {
        // Unit tests on a computer point to a build of the bridge for that computer.
        // Each test environment loads its own copy (Java allows one library file per class loader).
        val hostBuild = System.getProperty("enclave.native")
        if (hostBuild == null) System.loadLibrary("enclave_jni")
        else {
            val src = java.io.File(hostBuild)
            val copy = java.io.File.createTempFile("enclave_jni", "." + src.extension).apply { deleteOnExit() }
            src.copyTo(copy, overwrite = true)
            System.load(copy.path)
        }
    }

    @JvmStatic external fun format(path: String, blocks: Long): Long
    @JvmStatic external fun open(path: String): Long
    @JvmStatic external fun close(handle: Long)
    @JvmStatic external fun blocks(handle: Long): Long
    @JvmStatic external fun unlock(handle: Long, key: ByteArray): Int
    @JvmStatic external fun create(handle: Long, key: ByteArray): Int
    @JvmStatic external fun len(handle: Long, volume: Int): Long
    @JvmStatic external fun read(handle: Long, volume: Int, offset: Long, buf: ByteArray, off: Int, len: Int): Int
    @JvmStatic external fun write(handle: Long, volume: Int, offset: Long, buf: ByteArray, off: Int, len: Int)
    @JvmStatic external fun setLen(handle: Long, volume: Int, len: Long)
    @JvmStatic external fun flush(handle: Long)
    @JvmStatic external fun destroy(handle: Long, volume: Int)

    /** Bytes of a volume's data in each 4 KiB block on the disk (the crate's PAYLOAD). */
    const val PAYLOAD = 4096 - 24 - 16
}
