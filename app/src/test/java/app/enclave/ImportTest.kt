package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.DirStorage
import app.enclave.vault.Entry
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
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/**
 * Importing: files moved into the vault sometimes couldn't be opened afterwards (0.5.1 and
 * earlier). These go through the same calls the app makes, on the real container storage.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ImportTest {
    private fun tmp(): File = Files.createTempDirectory("enclave").toFile()
    private fun src(bytes: ByteArray, name: String) = File(tmp(), name).apply { writeBytes(bytes) }
    private fun segs(dir: File) = Segments(dir, 2048)

    private fun VaultStore.bytes(e: Entry): ByteArray = ByteArrayOutputStream().also { export(e, it) }.toByteArray()
    private fun VaultStore.named(name: String) = entries.value.first { it.name == name }

    /** A vault that has had a file deleted and was then locked, which is where 0.5.1 went wrong. */
    private fun vaultWithFreedSpace(dir: File, master: ByteArray, keep: Map<String, ByteArray>) {
        segs(dir).use { s ->
            val store = VaultStore(ContainerStorage.create(s, master, migrated = true), master.copyOf())
            val gone = store.importFile(src(Aead.random(900_000), "gone.bin"), null)
            keep.forEach { (n, b) -> store.importFile(src(b, n), null) }
            store.delete(gone)
            store.rename(store.named(keep.keys.first()), keep.keys.first())
            store.createFolder("folder", null)
            store.close()
        }
    }

    @Test
    fun twoImportsAfterReopeningBothStayReadable() {
        val dir = tmp()
        val master = Aead.random(32)
        val files = linkedMapOf("keep.jpg" to Aead.random(250_000))
        vaultWithFreedSpace(dir, master, files)

        segs(dir).use { s ->
            val store = VaultStore(ContainerStorage.open(s, master, readOnly = false)!!, master.copyOf())
            for (n in listOf("a.mp4", "b.mp4", "c.jpg")) {
                val b = Aead.random(600_000 + n.length)
                files[n] = b
                val e = store.importFile(src(b, n), null)
                assertEquals(b.size.toLong(), e.size)
            }
            // The first one imported is still whole after the ones that followed it.
            files.forEach { (n, b) ->
                assertTrue("$n verifies", store.verify(store.named(n)))
                assertArrayEquals(n, b, store.bytes(store.named(n)))
            }
            store.close()
        }
        segs(dir).use { s ->
            val store = VaultStore(ContainerStorage.open(s, master, readOnly = false)!!, master.copyOf())
            assertEquals(files.keys + "folder", store.entries.value.map { it.name }.toSet())
            files.forEach { (n, b) ->
                assertTrue("$n verifies after reopening", store.verify(store.named(n)))
                assertArrayEquals(n, b, store.bytes(store.named(n)))
            }
            store.close()
        }
    }

    @Test
    fun importsRunningAtOnceDoNotShareSpace() {
        val dir = tmp()
        val master = Aead.random(32)
        val files = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()
        files["keep.jpg"] = Aead.random(250_000)
        vaultWithFreedSpace(dir, master, files.toMap())

        segs(dir).use { s ->
            val store = VaultStore(ContainerStorage.open(s, master, readOnly = false)!!, master.copyOf())
            val failures = CopyOnWriteArrayList<Throwable>()
            (0 until 4).map { t ->
                thread {
                    runCatching {
                        repeat(5) { i ->
                            val name = "t$t-$i.bin"
                            val b = Aead.random(40_000 + 90_000 * ((t + i) % 4))
                            files[name] = b
                            store.importFile(src(b, name), null)
                            // What the file list does while imports run: previews and renames.
                            store.thumbnail(store.named(name))
                            if (i % 2 == 0) store.rename(store.named(name), name)
                        }
                    }.onFailure { failures += it }
                }
            }.forEach { it.join() }
            assertEquals(emptyList<Throwable>(), failures.toList())
            files.forEach { (n, b) ->
                assertTrue("$n verifies", store.verify(store.named(n)))
                assertArrayEquals(n, b, store.bytes(store.named(n)))
            }
            store.close()
        }
        segs(dir).use { s ->
            val store = VaultStore(ContainerStorage.open(s, master, readOnly = false)!!, master.copyOf())
            assertEquals(files.size, store.entries.value.count { !it.folder })
            files.forEach { (n, b) -> assertArrayEquals(n, b, store.bytes(store.named(n))) }
            store.close()
        }
    }

    /** Storage that damages one byte of every file (not preview) written through it. */
    private class Damaging(private val base: Storage) : Storage by base {
        override fun put(name: String, write: (OutputStream) -> Unit) {
            if (name.endsWith(".t")) return base.put(name, write)
            base.put(name) { out ->
                val all = ByteArrayOutputStream().also(write).toByteArray()
                all[all.size / 2] = (all[all.size / 2].toInt() xor 1).toByte()
                out.write(all)
            }
        }
    }

    @Test
    fun aFileThatDidNotStoreWholeIsRefusedAndNeverListed() {
        val dir = tmp()
        val master = Aead.random(32)
        val store = VaultStore(Damaging(DirStorage(dir)), master.copyOf())
        val original = src(Aead.random(200_000), "photo.jpg")
        val result = runCatching { store.importFile(original, null) }
        assertTrue(result.isFailure)
        assertEquals(VaultStore.NOT_STORED, result.exceptionOrNull()!!.message)
        assertEquals(emptyList<Entry>(), store.entries.value)
        assertEquals("nothing is left behind", emptySet<String>(), store.storage.names())
        assertTrue("the original is untouched", original.exists())
        store.close()
        // Nor is it there the next time the vault opens.
        VaultStore(dir, master.copyOf()).apply { assertEquals(emptyList<Entry>(), entries.value); close() }
    }

    @Test
    fun aSourceThatEndsEarlyIsRefused() {
        val store = VaultStore(tmp(), Aead.random(32))
        val real = src(Aead.random(10_000), "cut.bin")
        // The file system says it's longer than what can be read from it.
        val cut = object : File(real.path) {
            override fun length() = super.length() + 500
        }
        assertTrue(runCatching { store.importFile(cut, null) }.isFailure)
        assertEquals(emptyList<Entry>(), store.entries.value)
        assertEquals(emptySet<String>(), store.storage.names())
        // The same file read whole goes in.
        assertEquals(10_000L, store.importFile(real, null).size)
        store.close()
    }

    @Test
    fun verifyFindsDamageDoneAfterAnImportAndDoesNotThrow() {
        val dir = tmp()
        val master = Aead.random(32)
        val store = VaultStore(dir, master.copyOf())
        val a = store.importFile(src(Aead.random(300_000), "a.bin"), null)
        val b = store.importFile(src(Aead.random(300_000), "b.bin"), null)
        val c = store.importFile(src(Aead.random(300_000), "c.bin"), null)
        val empty = store.importFile(src(ByteArray(0), "empty.bin"), null)
        assertTrue(store.verify(a)); assertTrue(store.verify(b)); assertTrue(store.verify(c)); assertTrue(store.verify(empty))

        // The start of one file is written over (what a later import did in 0.5.1), another is cut short.
        RandomAccessFile(File(dir, a.id), "rw").use { it.seek(0); it.write(Aead.random(70_000)) }
        RandomAccessFile(File(dir, b.id), "rw").use { it.setLength(it.length() - 1) }
        assertFalse(store.verify(a))
        assertFalse(store.verify(b))
        assertTrue(store.verify(c))
        // A file whose blob is gone altogether.
        File(dir, c.id).delete()
        assertFalse(store.verify(c))
        store.close()

        // Files from before this version have no remembered hash: every chunk is still checked.
        val again = VaultStore(dir, master.copyOf())
        assertFalse(again.verify(again.named("a.bin")))
        assertTrue(again.verify(again.named("empty.bin")))
        again.close()
    }
}
