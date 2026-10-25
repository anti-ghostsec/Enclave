package app.enclave

import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import app.enclave.vault.ContainerStorage
import app.enclave.vault.DirStorage
import app.enclave.vault.Migration
import app.enclave.vault.Segments
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
import java.nio.ByteBuffer
import java.nio.file.Files
import javax.crypto.Cipher

/** Moving a real old-format vault into containers, including interruptions. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class MigrationTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()

    /** An old-format vault: some padded files, one unpadded (version 1) file, folders and settings. */
    private fun oldVault(master: ByteArray, contents: List<ByteArray>): Pair<File, List<String>> {
        val dir = tmp()
        val store = VaultStore(dir, master.copyOf())
        store.createFolder("Photos", null)
        val ids = contents.mapIndexed { i, b ->
            val src = File.createTempFile("src", ".bin").apply { writeBytes(b) }
            store.importFile(src, null).id
        }
        // Make the first file the old unpadded format, as the very first release wrote it.
        val first = store.entries.value.first { it.id == ids[0] }
        writeVersion1(store.keyBytes(first), contents[0], File(dir, first.id))
        store.updateSettings { it.copy(sort = "size", grid = false) }
        store.close()
        return dir to ids
    }

    private fun writeVersion1(key: ByteArray, plain: ByteArray, to: File) {
        val prefix = Aead.random(8)
        val out = ByteArrayOutputStream()
        out.write("ENCF".toByteArray()); out.write(1); out.write(prefix)
        val chunks = if (plain.isEmpty()) listOf(plain) else plain.toList().chunked(ChunkedCipher.CHUNK).map { it.toByteArray() }
        chunks.forEachIndexed { i, c ->
            val nonce = ByteBuffer.allocate(12).put(prefix).putInt(i).array()
            val aad = ByteBuffer.allocate(5).putInt(i).put(if (i == chunks.size - 1) 1 else 0).array()
            out.write(Aead.raw(Cipher.ENCRYPT_MODE, key, nonce, c, aad))
        }
        to.writeBytes(out.toByteArray())
    }

    private fun snapshot(dir: File) = dir.listFiles()!!.associate { it.name to it.readBytes().contentHashCode() }

    private fun assertVaultMatches(store: VaultStore, contents: List<ByteArray>, ids: List<String>) {
        assertEquals(contents.size + 1, store.entries.value.size) // + the folder
        assertTrue(store.entries.value.any { it.folder && it.name == "Photos" })
        ids.forEachIndexed { i, id ->
            val e = store.entries.value.first { it.id == id }
            store.reader(e).use { assertArrayEquals("file $i", contents[i], it.inputStream().readBytes()) }
        }
        assertEquals("size", store.settings.value.sort)
        assertFalse(store.settings.value.grid)
    }

    @Test
    fun movesEverythingByteForByte() {
        val master = Aead.random(32)
        val contents = List(12) { Aead.random(it * 150_000 + 3) }
        val (dir, ids) = oldVault(master, contents)
        val before = snapshot(dir)

        val containers = tmp()
        Segments(containers, 1024).use { s ->
            val target = ContainerStorage.create(s, master, migrated = false)
            Migration.run(DirStorage(dir), target, {}, { false })
            assertTrue(target.migrated)
            // The old vault is untouched by the move itself.
            assertEquals(before, snapshot(dir))
            assertVaultMatches(VaultStore(target, master.copyOf()), contents, ids)
        }
        // And it all reopens from the containers alone.
        dir.deleteRecursively()
        Segments(containers, 1024).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertTrue(cs.migrated)
            assertVaultMatches(VaultStore(cs, master.copyOf()), contents, ids)
        }
    }

    @Test
    fun anInterruptedMoveLosesNothingAndCarriesOn() {
        val master = Aead.random(32)
        val contents = List(10) { Aead.random(400_000 + it) }
        val (dir, ids) = oldVault(master, contents)
        val before = snapshot(dir)
        val containers = tmp()

        // First attempt: stopped part-way (the vault locked).
        Segments(containers, 1024).use { s ->
            val target = ContainerStorage.create(s, master, migrated = false)
            var calls = 0
            val stopped = runCatching { Migration.run(DirStorage(dir), target, {}, { ++calls > 8 }) }
            assertTrue(stopped.exceptionOrNull() is Migration.Cancelled)
            target.close()
        }
        assertEquals("old vault untouched", before, snapshot(dir))

        // A crash mid-copy: containers closed without saving.
        Segments(containers, 1024).use { s ->
            val target = ContainerStorage.open(s, master, readOnly = false)!!
            assertFalse(target.migrated)
            var calls = 0
            runCatching { Migration.run(DirStorage(dir), target, {}, { ++calls > 14 }) }
            s.all.forEach { app.enclave.vault.Native.close(it.handle) }
        }
        assertEquals("old vault untouched", before, snapshot(dir))

        // Next unlock: carries on and finishes.
        Segments(containers, 1024).use { s ->
            val target = ContainerStorage.open(s, master, readOnly = false)!!
            assertFalse(target.migrated)
            Migration.run(DirStorage(dir), target, {}, { false })
            assertTrue(target.migrated)
            assertVaultMatches(VaultStore(target, master.copyOf()), contents, ids)
        }
    }

    @Test
    fun newFilesAfterTheMoveWorkLikeBefore() {
        val master = Aead.random(32)
        val (dir, _) = oldVault(master, List(3) { Aead.random(10_000) })
        Segments(tmp(), 1024).use { s ->
            val target = ContainerStorage.create(s, master, migrated = false)
            Migration.run(DirStorage(dir), target, {}, { false })
            val store = VaultStore(target, master.copyOf())
            val extra = Aead.random(2_000_000)
            val e = store.importFile(File.createTempFile("new", ".bin").apply { writeBytes(extra) }, null)
            store.rename(e, "renamed.bin")
            store.delete(store.entries.value.filter { !it.folder }.take(1).map { it.id })
            store.reader(store.entries.value.first { it.id == e.id }).use { assertArrayEquals(extra, it.inputStream().readBytes()) }
            assertEquals(4, store.entries.value.size) // folder + 2 old + 1 new
            store.close()
        }
    }
}
