package app.enclave

import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile

/** Runs on the PC (no phone needed): the padded file format and Padmé sizes. */
class PaddingTest {
    private fun encrypt(key: ByteArray, plain: ByteArray): Pair<File, Long> {
        val f = File.createTempFile("enc", ".bin").apply { deleteOnExit() }
        val real = f.outputStream().use { ChunkedCipher.encrypt(key, plain.inputStream(), it) }
        return f to real
    }

    @Test
    fun padmeRoundsUpWithSmallOverhead() {
        assertEquals(512, ChunkedCipher.padme(0))
        assertEquals(512, ChunkedCipher.padme(300))
        for (len in listOf(513L, 1000L, 4097L, 65_537L, 1_000_000L, 12_345_678L, 3_000_000_000L)) {
            val p = ChunkedCipher.padme(len)
            assertTrue("$len -> $p", p >= len)
            assertTrue("overhead for $len", (p - len).toDouble() / len < 0.12)
            assertEquals("stable", p, ChunkedCipher.padme(p))
        }
        // Many different sizes collapse onto the same padded size.
        assertEquals(ChunkedCipher.padme(10_000_001), ChunkedCipher.padme(10_100_000))
    }

    @Test
    fun paddedRoundTripHidesExactSize() {
        val key = Aead.random(32)
        for (size in listOf(0, 1, 511, 513, ChunkedCipher.CHUNK - 1, ChunkedCipher.CHUNK, ChunkedCipher.CHUNK + 1, 300_001, 1_000_003)) {
            val plain = Aead.random(size)
            val (f, real) = encrypt(key, plain)
            assertEquals(size.toLong(), real)
            assertEquals(2, ChunkedCipher.versionOf(f))
            val padded = ChunkedCipher.padme(size.toLong())
            val chunks = (padded + ChunkedCipher.CHUNK - 1) / ChunkedCipher.CHUNK
            assertEquals("file length reveals only the padded size", ChunkedCipher.HEADER + padded + chunks * 16, f.length())
            ChunkedCipher.Reader(f, key, real).use { r ->
                assertEquals(size.toLong(), r.size)
                assertArrayEquals(plain, r.inputStream().readBytes())
                if (size > 20) {
                    val buf = ByteArray(9)
                    assertEquals(9, r.read((size / 2).toLong(), buf, 0, 9))
                    assertArrayEquals(plain.copyOfRange(size / 2, size / 2 + 9), buf)
                }
            }
        }
    }

    @Test
    fun tamperingTruncationAndWrongKeyFail() {
        val key = Aead.random(32)
        val plain = Aead.random(200_000)
        val (f, real) = encrypt(key, plain)
        RandomAccessFile(f, "rw").use { it.seek(5000); val b = it.read(); it.seek(5000); it.write(b xor 1) }
        assertTrue(runCatching { ChunkedCipher.Reader(f, key, real).use { it.inputStream().readBytes() } }.isFailure)

        val (g, realG) = encrypt(key, plain)
        RandomAccessFile(g, "rw").use { it.setLength(ChunkedCipher.HEADER + 3L * (ChunkedCipher.CHUNK + 16)) }
        assertTrue(runCatching { ChunkedCipher.Reader(g, key, realG).use { it.inputStream().readBytes() } }.isFailure)

        val (h, realH) = encrypt(key, plain)
        assertTrue(runCatching { ChunkedCipher.Reader(h, Aead.random(32), realH).use { it.inputStream().readBytes() } }.isFailure)
    }
}
