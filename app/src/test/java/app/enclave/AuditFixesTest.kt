package app.enclave

import app.enclave.crypto.Aead
import app.enclave.ui.freeName
import app.enclave.ui.safeFileName
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
import java.nio.file.Files

/** Fixes from the October 2026 audit. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AuditFixesTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()
    private fun src(bytes: ByteArray, name: String = "x.bin") =
        File(tmp(), name).apply { writeBytes(bytes) }

    @Test
    fun namesNeverBecomePaths() {
        assertEquals("evil.txt", safeFileName("../../evil.txt"))
        assertEquals("evil.txt", safeFileName("..\\..\\evil.txt"))
        assertEquals("file", safeFileName(".."))
        assertEquals("file", safeFileName("."))
        assertEquals("file", safeFileName("a/"))
        assertEquals("ok.jpg", safeFileName("ok.jpg"))
        val dir = tmp()
        assertEquals(dir.canonicalFile, freeName(dir, "../../../escape").canonicalFile.parentFile)
    }

    @Test
    fun exportStaysInsideTheChosenFolder() {
        val master = Aead.random(32)
        val store = VaultStore(tmp(), master)
        val folder = store.entries.value.size.let { store.createFolder("..", null); store.entries.value.first { it.folder } }
        val a = store.importFile(src(byteArrayOf(1, 2, 3)), folder.id)
        val b = store.importFile(src(byteArrayOf(4, 5)), null)
        store.rename(a, "../../outside-a.bin")
        store.rename(b, "..\\..\\outside-b.bin")

        val parent = tmp()
        val target = File(parent, "export").apply { mkdirs() }
        val n = store.exportTo(store.entries.value.filter { it.parent == null }.map { it.id }, target, ::freeName)
        assertEquals(2, n)
        // Nothing was written next to (or above) the chosen folder.
        assertEquals(listOf("export"), parent.list()!!.toList())
        val written = target.walk().filter { it.isFile }.map { it.name }.toSet()
        assertEquals(setOf("outside-a.bin", "outside-b.bin"), written)
        store.close()
    }

    @Test
    fun aDecoyOnItsOwnAcceptsChangesButKeepsNoneOfThem() {
        val dir = tmp()
        val decoy = Aead.random(32)
        val original = Aead.random(300_000)
        Segments(dir, 1024).use { s ->
            val cs = ContainerStorage.create(s, decoy, migrated = true)
            VaultStore(cs, decoy.copyOf()).apply { importFile(src(original, "photo.jpg"), null); close() }
        }
        // Opened alone: everything an onlooker might try works.
        Segments(dir, 1024).use { s ->
            val store = VaultStore(SessionOnlyStorage(ContainerStorage.open(s, decoy, readOnly = true)!!), decoy.copyOf())
            val added = store.importFile(src(Aead.random(50_000), "new.txt"), null)
            store.rename(store.entries.value.first { it.name == "photo.jpg" }, "renamed.jpg")
            store.createFolder("Holiday", null)
            store.delete(listOf(added.id))
            store.importFile(src(byteArrayOf(9), "another.txt"), null)
            assertEquals(setOf("renamed.jpg", "Holiday", "another.txt"), store.entries.value.map { it.name }.toSet())
            store.close()
        }
        // Nothing reached the containers.
        Segments(dir, 1024).use { s ->
            val store = VaultStore(ContainerStorage.open(s, decoy, readOnly = true)!!, decoy.copyOf())
            assertEquals(listOf("photo.jpg"), store.entries.value.map { it.name })
            store.reader(store.entries.value[0]).use { assertArrayEquals(original, it.inputStream().readBytes()) }
            store.close()
        }
    }

    @Test
    fun aHalfMadeContainerIsThrownAway() {
        val dir = tmp()
        File(dir, "0.tmp").writeBytes(ByteArray(4096 * 64))
        Segments(dir, 1024).use { s ->
            assertTrue(s.all.isEmpty())
            assertFalse(File(dir, "0.tmp").exists())
            s.add()
            assertEquals(listOf("0"), dir.list()!!.toList())
        }
    }
}
