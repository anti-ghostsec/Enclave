package app.enclave.crypto

import java.io.Closeable
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import javax.crypto.Cipher

/**
 * Encrypted file format, designed for random access (so videos can be streamed and seeked
 * without ever writing plaintext to disk):
 *
 *   "ENCF" | version(1) | noncePrefix(8) | chunk0 | chunk1 | ... | chunkN
 *
 * Version 2 pads the plaintext with zeros up to a Padmé length before encrypting, so the
 * encrypted size no longer reveals the exact original size (which could link a file to a known
 * original). The real size lives in the encrypted index. Version 1 files have no padding.
 *
 * Each chunk is up to 64 KiB of plaintext sealed with AES-256-GCM using
 * nonce = noncePrefix || chunkIndex, and AAD = chunkIndex || isFinal. Binding the index and
 * the final flag stops chunks from being reordered, duplicated or the file truncated.
 * Each file has its own random key, stored in the encrypted index.
 */
object ChunkedCipher {
    const val CHUNK = 64 * 1024
    private val MAGIC = byteArrayOf('E'.code.toByte(), 'N'.code.toByte(), 'C'.code.toByte(), 'F'.code.toByte())
    const val VERSION_PLAIN: Byte = 1
    const val VERSION_PADDED: Byte = 2
    private const val MIN_PADDED = 512L
    const val HEADER = 4 + 1 + 8
    private const val SEALED_CHUNK = CHUNK + Aead.TAG_BYTES

    private fun nonce(prefix: ByteArray, index: Int) =
        ByteBuffer.allocate(Aead.NONCE_BYTES).put(prefix).putInt(index).array()

    private fun aad(index: Int, final: Boolean) =
        ByteBuffer.allocate(5).putInt(index).put(if (final) 1 else 0).array()

    /**
     * Padmé (Nikitin et al., "Reducing Metadata Leakage from Encrypted Files", PETS 2019): rounds
     * a length up so only O(log log n) bits of it are revealed, with at most ~12% overhead
     * (under 3% for files over a few MB).
     */
    fun padme(length: Long): Long {
        if (length <= MIN_PADDED) return MIN_PADDED
        val e = 63 - java.lang.Long.numberOfLeadingZeros(length)
        val s = 32 - Integer.numberOfLeadingZeros(e)
        val mask = (1L shl (e - s)) - 1
        return (length + mask) and mask.inv()
    }

    /** Feeds the source, then zeros up to the Padmé length. Remembers the real length. */
    private class Padded(private val src: InputStream) : InputStream() {
        var real = 0L
        private var target = -1L
        private var produced = 0L

        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (target < 0) {
                val n = src.read(b, off, len)
                if (n >= 0) { real += n; produced += n; return n }
                target = padme(real)
            }
            val left = target - produced
            if (left <= 0) return -1
            val n = minOf(left, len.toLong()).toInt()
            b.fill(0, off, off + n)
            produced += n
            return n
        }
    }

    /** Encrypts [input] into [out], padded. Returns the real (unpadded) plaintext length. */
    fun encrypt(key: ByteArray, source: InputStream, out: OutputStream): Long {
        val input = Padded(source)
        val prefix = Aead.random(8)
        out.write(MAGIC); out.write(byteArrayOf(VERSION_PADDED)); out.write(prefix)
        var cur = ByteArray(CHUNK)
        var next = ByteArray(CHUNK)
        var curLen = readFully(input, cur)
        var index = 0
        var total = 0L
        while (true) {
            val nextLen = if (curLen == CHUNK) readFully(input, next) else 0
            val final = nextLen == 0
            val ct = Aead.raw(Cipher.ENCRYPT_MODE, key, nonce(prefix, index), cur.copyOf(curLen), aad(index, final))
            out.write(ct)
            total += curLen
            if (final) break
            index++
            val t = cur; cur = next; next = t
            curLen = nextLen
        }
        cur.fill(0); next.fill(0)
        check(total == padme(input.real)) { "padding mismatch" }
        return input.real
    }

    private fun readFully(input: InputStream, buf: ByteArray): Int {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) break
            off += n
        }
        return off
    }

    /** The format version of an encrypted file, or -1 if it isn't one. */
    fun versionOf(file: File): Int = runCatching {
        RandomAccessFile(file, "r").use { raf ->
            val head = ByteArray(5).also { raf.readFully(it) }
            if (head.copyOfRange(0, 4).contentEquals(MAGIC)) head[4].toInt() else -1
        }
    }.getOrDefault(-1)

    /**
     * Random-access reader over an encrypted file. [realSize] is the original length from the
     * index; it's required to strip the padding from version 2 files.
     */
    class Reader(private val source: BlobSource, private val key: ByteArray, realSize: Long) : Closeable {
        constructor(file: File, key: ByteArray, realSize: Long) : this(FileBlob(file), key, realSize)

        private val prefix: ByteArray
        private val chunks: Int
        val size: Long

        private var cachedIndex = -1
        private var cached = ByteArray(0)

        init {
            val head = ByteArray(HEADER)
            source.readFully(0, head)
            val version = head[4]
            require(head.copyOfRange(0, 4).contentEquals(MAGIC) && (version == VERSION_PLAIN || version == VERSION_PADDED)) { "not an Enclave file" }
            prefix = head.copyOfRange(5, HEADER)
            val ctLen = source.length - HEADER
            chunks = ((ctLen + SEALED_CHUNK - 1) / SEALED_CHUNK).toInt()
            val stored = ctLen - chunks.toLong() * Aead.TAG_BYTES
            size = if (version == VERSION_PADDED) {
                require(realSize in 0..stored) { "size doesn't fit the file" }
                realSize
            } else stored
        }

        private fun chunk(index: Int): ByteArray {
            if (index == cachedIndex) return cached
            val start = HEADER + index.toLong() * SEALED_CHUNK
            val len = minOf(SEALED_CHUNK.toLong(), source.length - start).toInt()
            val ct = ByteArray(len)
            source.readFully(start, ct)
            cached.fill(0)
            cached = Aead.raw(Cipher.DECRYPT_MODE, key, nonce(prefix, index), ct, aad(index, index == chunks - 1))
            cachedIndex = index
            return cached
        }

        /** Reads up to [len] bytes at [position]. Returns bytes read, or -1 at end of file. */
        @Synchronized
        fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
            if (position >= size) return -1
            var pos = position
            var done = 0
            while (done < len && pos < size) {
                val c = chunk((pos / CHUNK).toInt())
                val inChunk = (pos % CHUNK).toInt()
                val n = minOf((len - done).toLong(), (c.size - inChunk).toLong(), size - pos).toInt()
                System.arraycopy(c, inChunk, dst, off + done, n)
                done += n
                pos += n
            }
            return done
        }

        fun inputStream(): InputStream = object : InputStream() {
            private var pos = 0L
            override fun read(): Int {
                val b = ByteArray(1)
                return if (read(b, 0, 1) < 0) -1 else b[0].toInt() and 0xff
            }
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                val n = this@Reader.read(pos, b, off, len)
                if (n > 0) pos += n
                return n
            }
            override fun skip(n: Long): Long {
                val s = minOf(n, size - pos).coerceAtLeast(0)
                pos += s
                return s
            }
            override fun available(): Int = minOf(Int.MAX_VALUE.toLong(), size - pos).toInt()
        }

        override fun close() {
            cached.fill(0)
            source.close()
        }
    }
}
