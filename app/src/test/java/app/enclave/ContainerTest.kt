package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.Native
import app.enclave.vault.Segments
import app.enclave.vault.StorageFullException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * The real deniable storage crate (built for this computer), under Enclave's container layer.
 * Containers here are tiny (4 MiB) so growth and "full" are easy to reach.
 */
class ContainerTest {
    private val blocks = 1024L
    private fun newDir(): File = Files.createTempDirectory("containers").toFile()
    private fun segs(dir: File) = Segments(dir, blocks)

    private fun ContainerStorage.putBytes(name: String, b: ByteArray) = put(name) { it.write(b) }
    private fun ContainerStorage.bytes(name: String) = open(name).use { it.readAll() }

    @Test
    fun storesReopensAndKeepsEverything() {
        val dir = newDir()
        val master = Aead.random(32)
        val files = (0 until 20).associate { "f$it" to Aead.random(1 + it * 37_001) }
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            files.forEach { (n, b) -> cs.putBytes(n, b) }
            cs.saveIndex("index-1".toByteArray())
            cs.saveSettings("settings".toByteArray())
            cs.close()
        }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)
            assertNotNull(cs)
            cs!!
            assertTrue(cs.migrated)
            assertArrayEquals("index-1".toByteArray(), cs.loadIndex())
            assertArrayEquals("settings".toByteArray(), cs.loadSettings())
            assertEquals(files.keys, cs.names())
            files.forEach { (n, b) -> assertArrayEquals(n, b, cs.bytes(n)) }
            cs.close()
        }
        // A wrong key finds nothing at all.
        segs(dir).use { s -> assertNull(ContainerStorage.open(s, Aead.random(32), readOnly = false)) }
    }

    @Test
    fun growsByAddingContainersWhenFull() {
        val dir = newDir()
        val master = Aead.random(32)
        val big = (0 until 6).map { Aead.random(3 * 1024 * 1024 + it) } // ~18 MiB into 4 MiB containers
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            big.forEachIndexed { i, b -> cs.putBytes("b$i", b); cs.commit() }
            cs.saveIndex(byteArrayOf(1))
            assertTrue("added containers: ${s.all.size}", s.all.size >= 5)
            cs.close()
        }
        assertTrue(dir.listFiles()!!.all { it.length() == blocks * 4096 })
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            big.forEachIndexed { i, b -> assertArrayEquals(b, cs.bytes("b$i")) }
            cs.close()
        }
    }

    @Test
    fun uncommittedChangesVanishCleanlyAfterACrash() {
        val dir = newDir()
        val master = Aead.random(32)
        val keep = Aead.random(500_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            cs.putBytes("keep", keep)
            cs.saveIndex("v1".toByteArray())
            // Changes after the last save, then the power goes: the containers close unsaved.
            cs.putBytes("lost", Aead.random(800_000))
            cs.delete("keep")
            s.all.forEach { Native.close(it.handle) }
        }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertArrayEquals("v1".toByteArray(), cs.loadIndex())
            assertEquals(setOf("keep"), cs.names())
            assertArrayEquals(keep, cs.bytes("keep"))
            cs.close()
        }
    }

    @Test
    fun freedSpaceIsReusedWithoutTouchingOtherFiles() {
        val dir = newDir()
        val master = Aead.random(32)
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            val a = Aead.random(1_000_000); val b = Aead.random(1_000_000)
            cs.putBytes("a", a); cs.putBytes("b", b); cs.saveIndex(byteArrayOf(1))
            repeat(30) { i ->
                cs.delete("a")
                cs.saveIndex(byteArrayOf(2))
                val again = Aead.random(1_000_000 + i)
                cs.putBytes("a", again); cs.saveIndex(byteArrayOf(3))
                assertArrayEquals(again, cs.bytes("a"))
                assertArrayEquals("b survives round $i", b, cs.bytes("b"))
            }
            // 30 rewrites of 1 MB fit because freed space is reused.
            assertTrue(s.all.size <= 3)
            cs.close()
        }
    }

    @Test
    fun decoyIsReadOnlyAloneAndProtectedByTheRealVault() {
        val dir = newDir()
        val real = Aead.random(32)
        val decoy = Aead.random(32)
        val decoyFile = Aead.random(700_000)
        segs(dir).use { s ->
            val main = ContainerStorage.create(s, real, migrated = true)
            ContainerStorage.create(s, decoy, migrated = true).apply { putBytes("d", decoyFile); saveIndex(byteArrayOf(9)); close() }
            main.protect(ContainerStorage.volumeKey(decoy))
            repeat(8) { main.putBytes("r$it", Aead.random(1_500_000)); main.commit() }
            main.saveIndex(byteArrayOf(1))
            main.close()
        }
        segs(dir).use { s ->
            val d = ContainerStorage.open(s, decoy, readOnly = true)!!
            assertArrayEquals(decoyFile, d.bytes("d"))
            assertTrue(runCatching { d.putBytes("x", byteArrayOf(1)) }.exceptionOrNull() is StorageFullException)
            assertTrue(runCatching { d.saveIndex(byteArrayOf(1)) }.exceptionOrNull() is StorageFullException)
            d.close()
            val r = ContainerStorage.open(s, real, readOnly = false)!!
            assertEquals(8, r.names().size)
            r.close()
        }
    }

    @Test
    fun aDestroyedDecoyIsGone() {
        val dir = newDir()
        val decoy = Aead.random(32)
        segs(dir).use { s ->
            ContainerStorage.create(s, decoy, migrated = true).apply { putBytes("d", byteArrayOf(1, 2, 3)); saveIndex(byteArrayOf(1)); close() }
            ContainerStorage.destroy(s, decoy)
        }
        segs(dir).use { s -> assertNull(ContainerStorage.open(s, decoy, readOnly = true)) }
    }

    @Test
    fun anUnfinishedMoveIsMarkedSo() {
        val dir = newDir()
        val master = Aead.random(32)
        segs(dir).use { s -> ContainerStorage.create(s, master, migrated = false).close() }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertFalse(cs.migrated)
            cs.finishMigration()
            cs.close()
        }
        segs(dir).use { s -> assertTrue(ContainerStorage.open(s, master, readOnly = false)!!.migrated) }
    }
}
