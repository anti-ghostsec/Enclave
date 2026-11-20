package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.DirStorage
import app.enclave.vault.Storage
import app.enclave.vault.VaultStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException
import java.nio.file.Files

/** Fixes from the third audit (0.6.0) that can be checked on the PC. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ThirdAuditTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()

    private fun file(bytes: ByteArray): File = File(tmp(), "photo.jpg").apply { writeBytes(bytes) }

    /** Each file's id and key, as the store would back them up. */
    private fun keys(store: VaultStore) = store.entriesWithKeys().filter { !it.folder }.associate { it.id to it.key }

    @Test
    fun aFailedSaveLeavesTheKeysInMemoryAsTheyAreOnTheDisk() {
        val dir = tmp()
        val master = Aead.random(32)
        var failing = false
        val real = DirStorage(dir)
        val storage = object : Storage by real {
            override fun saveIndex(sealed: ByteArray) {
                if (failing) throw IOException("Storage is full")
                real.saveIndex(sealed)
            }
        }
        val store = VaultStore(storage, master.copyOf())
        val a = store.importFile(file(Aead.random(5000)), null)
        failing = true
        assertTrue(runCatching { store.importFile(file(Aead.random(7000)), null) }.isFailure)
        failing = false
        // Only the first file, with the same key as the index on the disk holds.
        val inMemory = keys(store)
        assertEquals(setOf(a.id), inMemory.keys)
        val reopened = VaultStore(DirStorage(dir), master.copyOf())
        assertEquals(keys(reopened), inMemory)
        assertTrue(inMemory.values.all { it.isNotEmpty() })
        store.close(); reopened.close()
    }

    @Test
    fun aBackupsListNeverHasAFileWithoutItsKey() {
        val store = VaultStore(tmp(), Aead.random(32))
        val files = List(4) { store.importFile(file(Aead.random(1000 + it)), null) }
        store.delete(files[1])
        val listed = store.entriesWithKeys()
        assertEquals(3, listed.size)
        assertFalse(listed.any { !it.folder && it.key.isEmpty() })
        store.close()
    }

    @Test
    fun everyUnlockOfOneVaultSharesOneOwnerAndOthersDiffer() {
        val master = Aead.random(32)
        val dir = tmp()
        val one = VaultStore(dir, master.copyOf())
        val again = VaultStore(dir, master.copyOf())
        val other = VaultStore(tmp(), Aead.random(32))
        assertTrue(one.shareOwner.contentEquals(again.shareOwner))
        assertFalse(one.shareOwner.contentEquals(other.shareOwner))
        one.close()
        // Zeroed at the lock with the vault's other keys.
        assertTrue(one.shareOwner.all { it == 0.toByte() })
        again.close(); other.close()
    }
}
