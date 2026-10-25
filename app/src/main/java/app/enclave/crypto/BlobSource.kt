package app.enclave.crypto

import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.RandomAccessFile

/** Random-access bytes of one stored blob: a file, a piece of a container, or memory. */
interface BlobSource : Closeable {
    val length: Long

    /** Reads up to [len] bytes at [position]. Returns bytes read, or -1 at the end. */
    fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int

    fun readFully(position: Long, dst: ByteArray, off: Int = 0, len: Int = dst.size - off) {
        var done = 0
        while (done < len) {
            val n = read(position + done, dst, off + done, len - done)
            if (n <= 0) throw EOFException("blob ended early")
            done += n
        }
    }

    /** The whole blob in memory. Only for small blobs. */
    fun readAll(): ByteArray = ByteArray(length.toInt()).also { readFully(0, it) }

    override fun close() {}
}

class FileBlob(file: File) : BlobSource {
    private val raf = RandomAccessFile(file, "r")
    override val length: Long = raf.length()

    @Synchronized
    override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
        if (position >= length) return -1
        raf.seek(position)
        return raf.read(dst, off, minOf(len.toLong(), length - position).toInt())
    }

    override fun close() = raf.close()
}

class BytesBlob(private val bytes: ByteArray) : BlobSource {
    override val length: Long get() = bytes.size.toLong()

    override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
        if (position >= bytes.size) return -1
        val n = minOf(len.toLong(), bytes.size - position).toInt()
        System.arraycopy(bytes, position.toInt(), dst, off, n)
        return n
    }
}
