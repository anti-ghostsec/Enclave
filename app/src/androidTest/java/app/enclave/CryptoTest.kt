package app.enclave

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import app.enclave.crypto.Kdf
import app.enclave.vault.Role
import app.enclave.vault.VaultManager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile

@RunWith(AndroidJUnit4::class)
class CryptoTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    private fun encryptToFile(key: ByteArray, plain: ByteArray): File {
        val f = File.createTempFile("enc", ".bin", ctx.cacheDir)
        f.outputStream().use { ChunkedCipher.encrypt(key, plain.inputStream(), it) }
        return f
    }

    @Test
    fun chunkedRoundTripAndRandomAccess() {
        val key = Aead.random(32)
        for (size in listOf(0, 1, ChunkedCipher.CHUNK - 1, ChunkedCipher.CHUNK, ChunkedCipher.CHUNK + 1, 300_001)) {
            val plain = Aead.random(size)
            val f = encryptToFile(key, plain)
            ChunkedCipher.Reader(f, key, size.toLong()).use { r ->
                assertEquals(size.toLong(), r.size)
                val out = ByteArrayOutputStream()
                r.inputStream().copyTo(out)
                assertArrayEquals("size $size", plain, out.toByteArray())
                if (size > 10) {
                    val pos = size / 2 - 3
                    val buf = ByteArray(7)
                    assertEquals(7, r.read(pos.toLong(), buf, 0, 7))
                    assertArrayEquals(plain.copyOfRange(pos, pos + 7), buf)
                }
            }
            f.delete()
        }
    }

    @Test
    fun tamperingAndTruncationAreDetected() {
        val key = Aead.random(32)
        val plain = Aead.random(200_000)
        val f = encryptToFile(key, plain)
        RandomAccessFile(f, "rw").use { it.seek(5000); val b = it.read(); it.seek(5000); it.write(b xor 1) }
        assertTrue(runCatching { ChunkedCipher.Reader(f, key, plain.size.toLong()).use { it.inputStream().readBytes() } }.isFailure)

        val g = encryptToFile(key, plain)
        // Drop the final chunk: the new last chunk wasn't sealed as "final", so reading must fail.
        RandomAccessFile(g, "rw").use { it.setLength(ChunkedCipher.HEADER + 3L * (ChunkedCipher.CHUNK + 16)) }
        assertTrue(runCatching { ChunkedCipher.Reader(g, key, plain.size.toLong()).use { it.inputStream().readBytes() } }.isFailure)

        assertTrue(runCatching { ChunkedCipher.Reader(encryptToFile(key, plain), Aead.random(32), plain.size.toLong()).use { it.inputStream().readBytes() } }.isFailure)
    }

    @Test
    fun vaultSlotsKeyfilesAndDuress() {
        VaultManager.init(ctx)
        assumeFalse("refusing to touch a real vault", VaultManager.exists())
        try {
            val t0 = System.nanoTime()
            val secret = Kdf.keyfileSecret(Aead.random(64).inputStream())
            val main = VaultManager.create("correct horse".toCharArray(), secret)
            Log.i("EnclaveTest", "Argon2id create took ${(System.nanoTime() - t0) / 1_000_000} ms")

            val again = VaultManager.unlock("correct horse".toCharArray(), secret)
            assertNotNull(again)
            assertEquals(Role.MAIN, again!!.role)
            assertArrayEquals(main.master, again.master)

            assertNull("keyfile required", VaultManager.unlock("correct horse".toCharArray(), null))
            assertNull("wrong password", VaultManager.unlock("wrong".toCharArray(), secret))

            val free = VaultManager.freeSlot(setOf(main.slot))!!
            VaultManager.setSlot(free, "duress".toCharArray(), null, Role.DECOY, Aead.random(32))
            assertEquals(Role.DECOY, VaultManager.unlock("duress".toCharArray(), null)!!.role)
            assertEquals(Role.MAIN, VaultManager.unlock("correct horse".toCharArray(), secret)!!.role)

            VaultManager.wipeAll()
            assertFalse(VaultManager.exists())
        } finally {
            VaultManager.wipeAll()
        }
    }
}
