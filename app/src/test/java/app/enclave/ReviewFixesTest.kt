package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.Segments
import app.enclave.vault.SessionOnlyStorage
import app.enclave.vault.VaultStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files

/** Fixes from the November 2026 review. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ReviewFixesTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()
    private fun src(bytes: ByteArray, name: String = "x.bin") = File(tmp(), name).apply { writeBytes(bytes) }

    /** A decoy opened on its own takes files far bigger than memory would, and keeps none. */
    @Test
    fun aDecoyOnItsOwnPutsBigFilesAsideAndRemovesThemWhenItLocks() {
        val dir = tmp()
        val scratch = File(tmp(), "scratch")
        val decoy = Aead.random(32)
        Segments(dir, 1024).use { s -> ContainerStorage.create(s, decoy, migrated = true).close() }
        val big = Aead.random(3_000_000)
        val small = Aead.random(2_000)
        Segments(dir, 1024).use { s ->
            val store = VaultStore(SessionOnlyStorage(ContainerStorage.open(s, decoy, readOnly = true)!!, scratch), decoy.copyOf())
            val a = store.importFile(src(big, "video.mp4"), null)
            val b = store.importFile(src(small, "note.txt"), null)
            // Only the big file's (encrypted) blob went to a file; nothing readable is in it.
            val aside = scratch.listFiles()!!.toList()
            assertEquals(1, aside.size)
            assertTrue(aside[0].length() >= big.size)
            assertEquals(VaultStore.FIXED_TIME, aside[0].lastModified())
            assertFalse(String(aside[0].readBytes(), Charsets.ISO_8859_1).contains(String(big.copyOf(64), Charsets.ISO_8859_1)))
            store.reader(a).use { assertArrayEquals(big, it.inputStream().readBytes()) }
            store.reader(b).use { assertArrayEquals(small, it.inputStream().readBytes()) }
            // Deleting a file removes what was put aside for it.
            store.delete(listOf(a.id))
            assertTrue(scratch.listFiles()!!.isEmpty())
            store.importFile(src(big, "again.mp4"), null)
            assertEquals(1, scratch.listFiles()!!.size)
            store.close()
        }
        // The folder stays, empty and undated, as it is whichever vault is open.
        assertTrue(scratch.listFiles()!!.isEmpty())
        assertEquals(VaultStore.FIXED_TIME, scratch.lastModified())
        // And the containers never heard of any of it.
        Segments(dir, 1024).use { s ->
            val store = VaultStore(ContainerStorage.open(s, decoy, readOnly = true)!!, decoy.copyOf())
            assertTrue(store.entries.value.isEmpty())
            store.close()
        }
    }

    /** Container files always carry the same fixed time, whatever was written and when. */
    @Test
    fun containersNeverShowWhenTheyWereWritten() {
        val dir = tmp()
        val master = Aead.random(32)
        fun times() = (dir.listFiles()!!.toList() + dir).map { it.lastModified() }.toSet()
        Segments(dir, 1024).use { s ->
            val store = VaultStore(ContainerStorage.create(s, master, migrated = true), master.copyOf())
            assertEquals(setOf(VaultStore.FIXED_TIME), times())
            // Enough to need a second container.
            repeat(3) { store.importFile(src(Aead.random(1_500_000), "f$it.bin"), null) }
            assertTrue(dir.listFiles()!!.size > 1)
            assertEquals(setOf(VaultStore.FIXED_TIME), times())
            store.close()
        }
        assertEquals(setOf(VaultStore.FIXED_TIME), times())
        // Opening alone restores it, as after a crash that left a real time behind.
        dir.listFiles()!!.forEach { it.setLastModified(System.currentTimeMillis()) }
        Segments(dir, 1024).use { assertEquals(setOf(VaultStore.FIXED_TIME), times()) }
    }

    /**
     * The vault's own header in its volume no longer counts saves: however often it's written,
     * the field holds the same value, and a vault whose header still holds a count opens as before.
     */
    @Test
    fun theVaultHeaderDoesNotCountSaves() {
        val dir = tmp()
        val master = Aead.random(32)
        fun generation(s: Segments): Long {
            val h = s.all.first().handle
            val v = app.enclave.vault.Native.unlock(h, ContainerStorage.volumeKey(master))
            val head = ByteArray(ContainerStorage.HEADER_BYTES)
            app.enclave.vault.Native.read(h, v, 0, head, 0, head.size)
            return ByteBuffer.wrap(head).order(ByteOrder.LITTLE_ENDIAN).getLong(8)
        }
        Segments(dir, 1024).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            repeat(25) { cs.saveIndex("index $it".toByteArray()) }
            cs.close()
            assertEquals(1L, generation(s))
        }
        // As an earlier version left it: a count of 4000 saves.
        Segments(dir, 1024).use { s ->
            val h = s.all.first().handle
            val v = app.enclave.vault.Native.unlock(h, ContainerStorage.volumeKey(master))
            val count = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(4000).array()
            app.enclave.vault.Native.write(h, v, 8, count, 0, 8)
            app.enclave.vault.Native.flush(h)
        }
        Segments(dir, 1024).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertArrayEquals("index 24".toByteArray(), cs.loadIndex())
            cs.saveIndex("later".toByteArray())
            cs.close()
            assertEquals(1L, generation(s))
        }
        Segments(dir, 1024).use { s ->
            assertArrayEquals("later".toByteArray(), ContainerStorage.open(s, master, readOnly = true)!!.loadIndex())
        }
    }
}
