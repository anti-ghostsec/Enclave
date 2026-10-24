package app.enclave

import app.enclave.crypto.Aead
import app.enclave.crypto.ChunkedCipher
import app.enclave.vault.VaultStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
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

/** Upgrading a vault made by an older version, on the PC (simulated Android). */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UpgradeTest {
    /** The original, unpadded format (version 1), as the first release wrote it. */
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

    private fun oldVault(plains: List<ByteArray>): Triple<File, ByteArray, List<String>> {
        val dir = Files.createTempDirectory("vault").toFile()
        val master = Aead.random(32)
        val store = VaultStore(dir, master.copyOf())
        val ids = plains.mapIndexed { i, p ->
            val src = File.createTempFile("src", ".bin").apply { writeBytes(p) }
            val e = store.importFile(src, null)
            val key = store.keyBytes(e)
            writeVersion1(key, p, File(dir, e.id))
            // Old-style preview: the sealed JPEG with no padding.
            File(dir, "${e.id}.t").writeBytes(Aead.seal(Aead.subkey(key, "thumbnail"), "fake-jpeg-$i".toByteArray()))
            e.id
        }
        store.close()
        return Triple(dir, master, ids)
    }

    @Test
    fun oldFilesArePaddedWithoutChangingContents() {
        val plains = listOf(Aead.random(0), Aead.random(1), Aead.random(70_000), Aead.random(1_234_567))
        val (dir, master, oldIds) = oldVault(plains)
        val store = VaultStore(dir, master.copyOf())
        store.upgradeOldFiles()

        val entries = store.entries.value
        assertEquals(plains.size, entries.size)
        entries.forEachIndexed { i, e ->
            assertNotEquals("re-encrypted under a new id", oldIds[i], e.id)
            assertFalse("old blob removed", File(dir, oldIds[i]).exists())
            assertFalse("old preview removed", File(dir, "${oldIds[i]}.t").exists())
            assertEquals(2, ChunkedCipher.versionOf(File(dir, e.id)))
            store.reader(e).use { assertArrayEquals("contents identical", plains[i], it.inputStream().readBytes()) }
            assertEquals(VaultStore.SEALED_THUMB_BYTES, File(dir, "${e.id}.t").length())
            assertEquals(VaultStore.FIXED_TIME, File(dir, e.id).lastModified())
        }
        // Reopening finds nothing left to do, and the vault still reads.
        store.close()
        val again = VaultStore(dir, master.copyOf())
        again.entries.value.forEachIndexed { i, e -> again.reader(e).use { assertArrayEquals(plains[i], it.inputStream().readBytes()) } }
        assertNull(again.upgrade.value)
    }

    @Test
    fun lockingMidUpgradeLosesNothing() {
        val plains = List(5) { Aead.random(100_000 + it) }
        val (dir, master, _) = oldVault(plains)
        val store = VaultStore(dir, master.copyOf())
        val t = Thread { store.upgradeOldFiles() }
        t.start()
        Thread.sleep(5)
        store.close()
        t.join()
        // Every file still opens with its exact contents, whichever version it ended up in.
        val reopened = VaultStore(dir, master.copyOf())
        assertEquals(5, reopened.entries.value.size)
        reopened.entries.value.forEachIndexed { i, e -> reopened.reader(e).use { assertArrayEquals(plains[i], it.inputStream().readBytes()) } }
        reopened.upgradeOldFiles()
        reopened.entries.value.forEachIndexed { i, e ->
            assertEquals(2, ChunkedCipher.versionOf(File(dir, e.id)))
            reopened.reader(e).use { assertArrayEquals(plains[i], it.inputStream().readBytes()) }
        }
        // Only the index, settings and one blob + one preview per file remain.
        val names = dir.listFiles()!!.map { it.name }.filter { it != "index.enc" && it != "settings.enc" }
        assertEquals(10, names.size)
        assertTrue(names.all { n -> reopened.entries.value.any { n == it.id || n == "${it.id}.t" } })
    }

    @Test
    fun duplicatesAreFoundByContentNotName() {
        val dir = Files.createTempDirectory("vault").toFile()
        val store = VaultStore(dir, Aead.random(32))
        val a = Aead.random(5000)
        val b = Aead.random(5000) // same size, different bytes: not a duplicate
        fun add(name: String, bytes: ByteArray) = store.importFile(File.createTempFile("dup", name).apply { writeBytes(bytes) }, null)
        add("a1", a); add("a2", a); add("a3", a); add("b", b); add("c", Aead.random(10))
        val groups = store.findDuplicates { _, _ -> }
        assertEquals(1, groups.size)
        assertEquals(3, groups[0].size)
        assertEquals(5, store.entries.value.size) // finding never deletes anything
    }
}
