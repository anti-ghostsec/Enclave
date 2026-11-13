package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.DuressSlot
import app.enclave.vault.EmptyStorage
import app.enclave.vault.Native
import app.enclave.vault.Segments
import app.enclave.vault.Session
import app.enclave.vault.VaultStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.Base64

/**
 * The real vault and its decoys share the containers. The real vault must have its decoys open
 * before it writes anything, and a decoy that got damaged anyway must not lock anyone out.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class DecoySafetyTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()
    private fun src(bytes: ByteArray, name: String) = File(tmp(), name).apply { writeBytes(bytes) }
    private fun segs(dir: File) = Segments(dir, 1024)
    private fun VaultStore.bytes(name: String): ByteArray =
        ByteArrayOutputStream().also { export(entries.value.first { e -> e.name == name }, it) }.toByteArray()

    private fun slot(decoy: ByteArray) = DuressSlot(1, "decoy", "decoy", master = Base64.getEncoder().encodeToString(decoy))

    @Test
    fun decoysAreProtectedBeforeTheRealVaultTidiesUp() {
        val dir = tmp()
        val real = Aead.random(32)
        val decoy = Aead.random(32)
        val decoyFile = Aead.random(900_000)
        val realFile = Aead.random(100_000)
        segs(dir).use { s ->
            val main = ContainerStorage.create(s, real, migrated = true)
            val store = VaultStore(main, real.copyOf())
            ContainerStorage.create(s, decoy, migrated = true).let { cs ->
                VaultStore(cs, decoy.copyOf()).apply { importFile(src(decoyFile, "d.jpg"), null); close() }
            }
            main.protect(ContainerStorage.volumeKey(decoy))
            store.updateSettings { it.copy(duress = listOf(slot(decoy))) }
            store.importFile(src(realFile, "r.jpg"), null)
            // What a kill in the middle of an import or a delete leaves: blobs the index doesn't
            // list. The next unlock removes them, which is a save.
            repeat(6) { i -> main.put("0000000000000000000000000000000$i") { it.write(Aead.random(150_000)) } }
            main.commit()
            store.close()
        }
        // Unlock after unlock, each starting with that tidying save.
        repeat(8) { round ->
            segs(dir).use { s ->
                val main = ContainerStorage.open(s, real, readOnly = false)!!
                var orphansWhenProtected = -1
                val store = VaultStore(main, real.copyOf()) { settings ->
                    orphansWhenProtected = main.names().size
                    Session.protectDecoys(main, settings)
                }
                if (round == 0) assertEquals("nothing was written before the decoys were protected", 8, orphansWhenProtected)
                assertEquals(setOf("r.jpg"), store.entries.value.map { it.name }.toSet())
                assertArrayEquals(realFile, store.bytes("r.jpg"))
                // Leave more for the next round to tidy.
                repeat(4) { i -> main.put("0000000000000000000000000000001$i") { it.write(Aead.random(120_000)) } }
                main.commit()
                store.close()
            }
        }
        segs(dir).use { s ->
            val d = VaultStore(Session.decoyStorage(s, decoy), decoy.copyOf())
            assertArrayEquals("the decoy is untouched", decoyFile, d.bytes("d.jpg"))
            d.close()
        }
    }

    /** A real vault and a decoy, where the real vault wrote without protecting the decoy until it broke. */
    private fun damagedDecoy(): Triple<File, ByteArray, ByteArray> {
        repeat(200) {
            val dir = tmp()
            val real = Aead.random(32)
            val decoy = Aead.random(32)
            segs(dir).use { s ->
                val main = ContainerStorage.create(s, real, migrated = true)
                ContainerStorage.create(s, decoy, migrated = true).apply { put("d") { it.write(Aead.random(900_000)) }; saveIndex(byteArrayOf(9)); close() }
                main.close()
            }
            segs(dir).use { s ->
                val main = ContainerStorage.open(s, real, readOnly = false)!!
                val store = VaultStore(main, real.copyOf())
                repeat(4) { i -> store.importFile(src(Aead.random(200_000), "r$i"), null) }
                store.close()
            }
            val damaged = segs(dir).use { s ->
                runCatching { Native.unlock(s.all[0].handle, ContainerStorage.volumeKey(decoy)) }.exceptionOrNull() is java.io.IOException
            }
            if (damaged) return Triple(dir, real, decoy)
            dir.deleteRecursively()
        }
        error("couldn't damage a decoy")
    }

    @Test
    fun aDamagedDecoyNeverStopsTheRealVaultOpening() {
        val (dir, real, decoy) = damagedDecoy()
        val added = Aead.random(150_000)
        segs(dir).use { s ->
            val main = ContainerStorage.open(s, real, readOnly = false)!!
            val store = VaultStore(main, real.copyOf()) { Session.protectDecoys(main, it.copy(duress = listOf(slot(decoy), DuressSlot(2, "decoy", "bad", master = "not base64!")))) }
            assertEquals(4, store.entries.value.size)
            assertTrue(store.entries.value.all { store.verify(it) })
            // And it keeps working.
            store.importFile(src(added, "new.bin"), null)
            assertArrayEquals(added, store.bytes("new.bin"))
            store.close()
        }
        segs(dir).use { s ->
            val main = ContainerStorage.open(s, real, readOnly = false)!!
            main.protect(ContainerStorage.volumeKey(decoy))
            val store = VaultStore(main, real.copyOf())
            assertArrayEquals(added, store.bytes("new.bin"))
            store.close()
        }
    }

    @Test
    fun aDamagedDecoyOpensAsAnEmptyVault() {
        val (dir, _, decoy) = damagedDecoy()
        segs(dir).use { s ->
            val storage = Session.decoyStorage(s, decoy)
            assertTrue(storage is EmptyStorage)
            val store = VaultStore(storage, decoy.copyOf())
            assertEquals(emptyList<Any>(), store.entries.value)
            store.close()
        }
        // A password with nothing behind it looks the same.
        segs(dir).use { s -> assertTrue(Session.decoyStorage(s, Aead.random(32)) is EmptyStorage) }
        // A decoy in good order still opens, read-only.
        val fine = tmp()
        segs(fine).use { s ->
            ContainerStorage.create(s, decoy, migrated = true).apply { put("d") { it.write(byteArrayOf(1)) }; saveIndex(byteArrayOf(9)); close() }
            val storage = Session.decoyStorage(s, decoy)
            assertFalse(storage is EmptyStorage)
            assertTrue(storage.readOnly)
        }
    }
}
