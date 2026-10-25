package app.enclave

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.Segments
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * Runs the real container code on a phone, in a throwaway folder in the app's cache (never the
 * vault), and logs how long things take, to size up a full move.
 */
@RunWith(AndroidJUnit4::class)
class ContainerSpeedTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun formatWriteAndReadOnRealStorage() {
        val dir = File(ctx.cacheDir, "container-speed-test").apply { deleteRecursively() }
        try {
            val master = Aead.random(32)
            val chunk = Aead.random(25 * 1024 * 1024)
            val t0 = System.nanoTime()
            Segments(dir, 131_072).use { s -> // 512 MiB
                val cs = ContainerStorage.create(s, master, migrated = true)
                val t1 = System.nanoTime()
                repeat(8) { cs.put("f$it") { out -> out.write(chunk) }; cs.commit() }
                cs.saveIndex(byteArrayOf(1))
                val t2 = System.nanoTime()
                val want = MessageDigest.getInstance("SHA-256").digest(chunk)
                repeat(8) { i ->
                    val got = MessageDigest.getInstance("SHA-256").digest(cs.open("f$i").use { it.readAll() })
                    assertArrayEquals(want, got)
                }
                val t3 = System.nanoTime()
                cs.close()
                fun ms(a: Long, b: Long) = (b - a) / 1_000_000
                Log.i("EnclaveSpeed", "format 512MiB: ${ms(t0, t1)} ms; write 200MiB: ${ms(t1, t2)} ms; read+check 200MiB: ${ms(t2, t3)} ms")
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
