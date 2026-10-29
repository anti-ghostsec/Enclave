package app.enclave

import app.enclave.crypto.Aead
import app.enclave.crypto.BlobSource
import app.enclave.vault.Backup
import app.enclave.vault.ContainerStorage
import app.enclave.vault.Segments
import app.enclave.vault.Storage
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
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class BackupTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()
    private fun src(bytes: ByteArray, name: String) = File(tmp(), name).apply { writeBytes(bytes) }
    private val pw = "correct horse battery".toCharArray()

    /** A vault with folders, a big file spanning several backup chunks, and an empty file. */
    private fun vault(): Triple<VaultStore, ByteArray, Map<String, ByteArray>> {
        val master = Aead.random(32)
        val store = VaultStore(tmp(), master.copyOf())
        store.createFolder("Trips", null)
        val trips = store.entries.value.first { it.folder }
        store.createFolder("2025", trips.id)
        val y2025 = store.entries.value.first { it.name == "2025" }
        val files = mapOf("a.jpg" to Aead.random(3_500_000), "b.txt" to Aead.random(100), "empty.bin" to ByteArray(0))
        store.importFile(src(files.getValue("a.jpg"), "a.jpg"), y2025.id)
        store.importFile(src(files.getValue("b.txt"), "b.txt"), null)
        store.importFile(src(files.getValue("empty.bin"), "empty.bin"), trips.id)
        return Triple(store, master, files)
    }

    private fun contents(store: VaultStore) = store.entries.value.filter { !it.folder }
        .associate { e -> e.name to store.reader(e).use { it.inputStream().readBytes() } }

    @Test
    fun restoresIntoAnotherVaultWithEverythingIntact() {
        val (store, master, files) = vault()
        val backup = File(tmp(), "backup.bin")
        Backup.create(store, master, pw, backup) { _, _ -> }
        assertFalse(File(backup.path + ".tmp").exists())

        // Into a different vault, in the containers, on "another phone".
        Segments(tmp(), 2048).use { s ->
            val other = Aead.random(32)
            val target = VaultStore(ContainerStorage.create(s, other, migrated = true), other.copyOf())
            target.importFile(src(byteArrayOf(7), "mine.txt"), null)
            val n = Backup.restore(backup, pw, target, "Restored") { _, _ -> }
            assertEquals(3, n)
            val restored = contents(target)
            files.forEach { (name, bytes) -> assertArrayEquals(name, bytes, restored[name]) }
            assertArrayEquals(byteArrayOf(7), restored["mine.txt"])
            // The folder structure comes back under one new folder.
            val root = target.entries.value.first { it.name == "Restored" }
            val trips = target.entries.value.first { it.name == "Trips" }
            assertEquals(root.id, trips.parent)
            val a = target.entries.value.first { it.name == "a.jpg" }
            assertEquals("Restored / Trips / 2025 / a.jpg", target.pathOf(a))
            target.close()
        }
        store.close()
    }

    @Test
    fun wrongPasswordDamageAndCutsAreRefused() {
        val (store, master, _) = vault()
        val backup = File(tmp(), "backup.bin")
        Backup.create(store, master, pw, backup) { _, _ -> }
        val target = VaultStore(tmp(), Aead.random(32))

        assertTrue(runCatching { Backup.restore(backup, "wrong".toCharArray(), target, "R") { _, _ -> } }.exceptionOrNull() is Backup.WrongPassword)

        val damaged = File(tmp(), "d.bin").apply { writeBytes(backup.readBytes()) }
        RandomAccessFile(damaged, "rw").use { it.seek(it.length() / 2); val b = it.read(); it.seek(it.length() / 2); it.write(b xor 1) }
        assertTrue(runCatching { Backup.restore(damaged, pw, target, "R") { _, _ -> } }.isFailure)

        val cut = File(tmp(), "c.bin").apply { writeBytes(backup.readBytes().copyOf((backup.length() - 1_100_000).toInt())) }
        assertTrue(runCatching { Backup.restore(cut, pw, target, "R") { _, _ -> } }.isFailure)

        // Failed restores add nothing.
        assertTrue(target.entries.value.isEmpty())
        assertTrue(target.storage.names().isEmpty())
        target.close(); store.close()
    }

    @Test
    fun theFileGivesNothingAway() {
        val (store, master, _) = vault()
        val backup = File(tmp(), "backup.bin")
        Backup.create(store, master, pw, backup) { _, _ -> }
        val bytes = backup.readBytes()
        val text = String(bytes, Charsets.ISO_8859_1)
        listOf("ENCF", "Trips", "a.jpg", "index", "master", "\"entries\"").forEach { assertFalse(it, text.contains(it)) }
        // Random-looking: every byte value turns up about equally often.
        val counts = IntArray(256).also { c -> bytes.forEach { c[it.toInt() and 0xff]++ } }
        val expected = bytes.size / 256.0
        assertTrue(counts.all { it > expected * 0.8 && it < expected * 1.2 })
        store.close()
    }

    @Test
    fun aFailedBackupLeavesNoFile() {
        val (store, master, _) = vault()
        // Storage that fails part-way through reading a file.
        val failing = object : Storage by store.storage {
            override fun open(name: String): BlobSource {
                val real = store.storage.open(name)
                return object : BlobSource by real {
                    override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int =
                        if (position > 1_000_000) throw IOException("disk error") else real.read(position, dst, off, len)
                }
            }
            override fun put(name: String, write: (OutputStream) -> Unit) = store.storage.put(name, write)
        }
        val dir = tmp()
        val backup = File(dir, "backup.bin")
        assertTrue(runCatching { Backup.create(VaultStore(failing, master.copyOf()), master, pw, backup) { _, _ -> } }.isFailure)
        assertTrue(dir.list()!!.isEmpty())
        store.close()
    }
}
