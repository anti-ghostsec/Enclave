package app.enclave

import app.enclave.crypto.Aead
import app.enclave.crypto.BlobSource
import app.enclave.crypto.ChunkedCipher
import app.enclave.vault.DirStorage
import app.enclave.vault.Backup
import app.enclave.vault.DuressSlot
import app.enclave.vault.Entry
import app.enclave.vault.ImportProblem
import app.enclave.vault.PlainPrefs
import app.enclave.vault.StorageFullException
import app.enclave.vault.Header
import app.enclave.vault.Storage
import app.enclave.vault.VaultManager
import app.enclave.vault.VaultStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.file.Files
import javax.crypto.Cipher

/** Fixes from the November 2026 audit (0.5.2) that aren't about the containers or importing. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecondAuditTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()

    private fun encrypted(key: ByteArray, plain: ByteArray): File =
        File(tmp(), "f").apply { outputStream().use { ChunkedCipher.encrypt(key, plain.inputStream(), it) } }

    /** The original, unpadded format (version 1), as the first release wrote it. */
    private fun version1(key: ByteArray, plain: ByteArray): File {
        val prefix = Aead.random(8)
        val out = ByteArrayOutputStream()
        out.write("ENCF".toByteArray()); out.write(1); out.write(prefix)
        val chunks = if (plain.isEmpty()) listOf(plain) else plain.toList().chunked(ChunkedCipher.CHUNK).map { it.toByteArray() }
        chunks.forEachIndexed { i, c ->
            val nonce = ByteBuffer.allocate(12).put(prefix).putInt(i).array()
            val aad = ByteBuffer.allocate(5).putInt(i).put(if (i == chunks.size - 1) 1 else 0).array()
            out.write(Aead.raw(Cipher.ENCRYPT_MODE, key, nonce, c, aad))
        }
        return File(tmp(), "v1").apply { writeBytes(out.toByteArray()) }
    }

    private fun read(f: File, key: ByteArray, size: Long) =
        ChunkedCipher.Reader(f, key, size).use { r -> r.size to r.inputStream().readBytes() }

    @Test
    fun changingTheVersionByteDoesNotMakeThePaddingPartOfTheFile() {
        val key = Aead.random(32)
        for (n in listOf(1, 600, 70_000, 200_001)) {
            val plain = Aead.random(n)
            val f = encrypted(key, plain)
            assertEquals(2, ChunkedCipher.versionOf(f))
            RandomAccessFile(f, "rw").use { it.seek(4); it.write(1) }
            val (size, bytes) = read(f, key, n.toLong())
            assertEquals(n.toLong(), size)
            assertArrayEquals(plain, bytes)
        }
    }

    @Test
    fun filesInTheFirstFormatReadExactlyAsBefore() {
        val key = Aead.random(32)
        for (n in listOf(0, 1, 65_536, 70_000, 300_000)) {
            val plain = Aead.random(n)
            val f = version1(key, plain)
            val (size, bytes) = read(f, key, n.toLong())
            assertEquals(n.toLong(), size)
            assertArrayEquals(plain, bytes)
            // Whatever size the caller has for it, an unpadded file is never read as longer or empty.
            assertArrayEquals(plain, read(f, key, 0).second)
            assertArrayEquals(plain, read(f, key, n + 5L).second)
            ChunkedCipher.Reader(f, key, n.toLong()).use { it.checkAll() }
        }
        // Padded files too: unchanged, and a size that can't be right is still refused.
        val plain = Aead.random(5000)
        val f = encrypted(key, plain)
        assertArrayEquals(plain, read(f, key, 5000).second)
        assertTrue(runCatching { read(f, key, 1_000_000) }.isFailure)
    }

    @Test
    fun lookingForAnOldFormatVaultLeavesNoDirectoryBehind() {
        val root = File(tmp(), "vaults")
        val dir = File(root, "0123456789abcdef01234567")
        val storage = DirStorage(dir)
        assertFalse(storage.hasVault)
        assertNull(storage.loadIndex())
        assertEquals(emptySet<String>(), storage.names())
        assertFalse("nothing was created by looking", root.exists())

        // Writing makes it, and an old-format vault works as before.
        val master = Aead.random(32)
        val store = VaultStore(storage, master.copyOf())
        val e = store.importFile(File(tmp(), "a.txt").apply { writeBytes(byteArrayOf(1, 2, 3)) }, null)
        store.close()
        assertTrue(DirStorage(dir).hasVault)
        val again = VaultStore(dir, master.copyOf())
        assertEquals(listOf(e.id), again.entries.value.map { it.id })
        again.close()
    }

    @Test
    fun emptyVaultDirectoriesAreRemovedAndOnesWithDataNeverAre() {
        val root = File(tmp(), "vaults")
        val empty1 = File(root, "aaaaaaaaaaaaaaaaaaaaaaaa").apply { mkdirs() }
        val empty2 = File(root, "bbbbbbbbbbbbbbbbbbbbbbbb").apply { mkdirs() }
        val used = File(root, "cccccccccccccccccccccccc").apply { mkdirs() }
        File(used, "index.enc").writeBytes(byteArrayOf(1))
        File(used, "0123456789abcdef0123456789abcdef").writeBytes(byteArrayOf(2))
        VaultManager.removeEmptyVaultDirs(root)
        assertFalse(empty1.exists()); assertFalse(empty2.exists())
        assertEquals(setOf("index.enc", "0123456789abcdef0123456789abcdef"), used.list()!!.toSet())
        assertArrayEquals(byteArrayOf(1), File(used, "index.enc").readBytes())

        // With nothing left the folder itself goes, and a missing one is no trouble.
        used.deleteRecursively()
        VaultManager.removeEmptyVaultDirs(root)
        assertFalse(root.exists())
        VaultManager.removeEmptyVaultDirs(root)
    }

    @Test
    fun aSettingsSaveThatFailsSaysSo() {
        var fail = false
        val base = DirStorage(tmp())
        val storage = object : Storage by base {
            override fun saveSettings(sealed: ByteArray) = if (fail) throw IOException("no room") else base.saveSettings(sealed)
            override fun open(name: String): BlobSource = base.open(name)
        }
        val store = VaultStore(storage, Aead.random(32))
        val entry = DuressSlot(2, "decoy", "x")
        assertTrue(store.updateSettings { it.copy(duress = it.duress + entry) })
        fail = true
        assertFalse(store.updateSettings { it.copy(duress = emptyList()) })
        assertEquals(listOf(entry), store.settings.value.duress)
        assertEquals("no room", store.problem.value)
        store.close()
        assertFalse(store.updateSettings { it })
    }

    @Test
    fun aBackupsListIsMadeSoundAndAnHonestOneIsLeftAlone() {
        val honest = listOf(
            Entry("f1", null, "top", folder = true), Entry("f2", "f1", "inner", folder = true),
            Entry("a", "f2", "a.jpg"), Entry("b", null, "b.jpg"),
        )
        assertEquals(honest, Backup.sound(honest))

        val crafted = listOf(
            Entry("x", "y", "x", folder = true), Entry("y", "x", "y", folder = true), // each other's parent
            Entry("self", "self", "self", folder = true),
            Entry("below", "x", "below.jpg"),
            Entry("dup", null, "first.jpg"), Entry("dup", null, "second.jpg"),
            Entry("lost", "nowhere", "lost.jpg"), Entry("infile", "dup", "in-a-file.jpg"),
            Entry("", null, "no id"),
        )
        val made = Backup.sound(crafted)
        assertEquals(listOf("x", "y", "self", "below", "dup", "lost", "infile"), made.map { it.id })
        assertEquals("first.jpg", made.first { it.id == "dup" }.name)
        assertNull(made.first { it.id == "x" }.parent)
        assertNull(made.first { it.id == "y" }.parent)
        assertNull(made.first { it.id == "self" }.parent)
        assertEquals("x", made.first { it.id == "below" }.parent)
        assertNull(made.first { it.id == "lost" }.parent)
        assertNull(made.first { it.id == "infile" }.parent)

        // And a list that got in some other way with a loop in it doesn't hang the vault.
        val store = VaultStore(tmp(), Aead.random(32))
        store.addRestored(listOf(Entry("x", "y", "x", folder = true), Entry("y", "x", "y", folder = true), Entry("f", "x", "f.jpg")))
        assertFalse(store.isWithin("f", "elsewhere"))
        assertTrue(store.isWithin("f", "y"))
        assertTrue(store.pathOf(store.entries.value.first { it.id == "f" }).endsWith("f.jpg"))
        store.move(listOf("x"), "y")
        store.close()
    }

    @Test
    fun theLockStateIsAlwaysSavedAtOneSize() {
        val small = PlainPrefs.paddedJson(emptyMap())
        val usual = PlainPrefs.paddedJson(mapOf("disguise" to "Default", "wipe_after" to "10", "failed" to "3"))
        val full = PlainPrefs.paddedJson(
            mapOf(
                "disguise" to "Çalculator – ✓", "calc_facade" to "true", "calc_salt" to "ab".repeat(16), "calc_kdf" to "cd".repeat(32),
                "auto_lock" to "300", "wipe_after" to "20", "failed" to "12", "failed_at" to "1794000000000",
                "failed_since_boot" to "123456789", "failed_boot" to "42", "main_in_containers" to "true",
            ),
        )
        assertEquals(2048, small.toByteArray().size)
        assertEquals(2048, usual.toByteArray().size)
        assertEquals(2048, full.toByteArray().size)
        // It's still the same JSON map, which earlier versions read too.
        val back = kotlinx.serialization.json.Json.decodeFromString<Map<String, String>>(usual)
        assertEquals(mapOf("disguise" to "Default", "wipe_after" to "10", "failed" to "3"), back - "_pad")
        // More than fits goes to the next size up, never over it.
        assertEquals(4096, PlainPrefs.paddedJson(mapOf("k" to "v".repeat(3000))).toByteArray().size)
    }

    @Test
    fun containersGetTheFixedTimeAtStart() {
        val dir = tmp()
        val a = File(dir, "0").apply { writeBytes(byteArrayOf(1)) }
        val b = File(dir, "1").apply { writeBytes(byteArrayOf(2)) }
        VaultManager.stampAll(dir)
        assertEquals(VaultStore.FIXED_TIME, a.lastModified())
        assertEquals(VaultStore.FIXED_TIME, b.lastModified())
        assertEquals(VaultStore.FIXED_TIME, dir.lastModified())
        VaultManager.stampAll(File(dir, "missing"))
        assertFalse(File(dir, "missing").exists())
    }

    @Test
    fun onlyEnclavesOwnWordingIsShownForAFailedImport() {
        assertEquals(": " + VaultStore.NOT_STORED, VaultStore.reasonToShow(ImportProblem(VaultStore.NOT_STORED)))
        assertEquals(": Storage is full", VaultStore.reasonToShow(StorageFullException()))
        assertEquals("", VaultStore.reasonToShow(java.io.FileNotFoundException("/storage/emulated/0/DCIM/secret name.jpg (No such file)")))
        assertEquals("", VaultStore.reasonToShow(IllegalStateException("anything")))
    }

    @Test
    fun aFreeSlotIsOneOfTheFreeOnes() {
        val seen = HashSet<Int>()
        repeat(200) { seen += VaultManager.freeSlot(setOf(1))!! }
        assertEquals(setOf(0, 2, 3), seen)
        assertEquals(2, VaultManager.freeSlot(setOf(0, 1, 3)))
        assertNull(VaultManager.freeSlot((0 until Header.SLOT_COUNT).toSet()))
    }
}
