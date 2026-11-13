package app.enclave

import app.enclave.crypto.Aead
import app.enclave.vault.ContainerStorage
import app.enclave.vault.Extent
import app.enclave.vault.Native
import app.enclave.vault.Segments
import app.enclave.vault.StorageFullException
import app.enclave.vault.mergeExtents
import app.enclave.vault.subtractExtents
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.int
import kotlinx.serialization.json.put
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
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

    // ---- The free list (0.5.2) -------------------------------------------------------------

    @Test
    fun extentsAreJoinedAndTakenApart() {
        assertEquals(
            listOf(Extent(0, 10, 30), Extent(0, 50, 5), Extent(1, 0, 7)),
            mergeExtents(listOf(Extent(1, 0, 7), Extent(0, 20, 20), Extent(0, 10, 10), Extent(0, 15, 10), Extent(0, 50, 5), Extent(0, 60, 0), Extent(0, -4, 8))),
        )
        val free = listOf(Extent(0, 0, 100), Extent(0, 200, 100), Extent(1, 0, 50))
        assertEquals(free, subtractExtents(free, emptyList()))
        assertEquals(free, subtractExtents(free, listOf(Extent(0, 100, 100), Extent(2, 0, 10), Extent(1, 50, 10))))
        assertEquals(
            listOf(Extent(0, 0, 10), Extent(0, 20, 70), Extent(0, 250, 50), Extent(1, 10, 40)),
            subtractExtents(free, listOf(Extent(0, 10, 10), Extent(0, 90, 160), Extent(1, 0, 10))),
        )
        // One used range across several free ones, and a free one wholly used.
        assertEquals(listOf(Extent(0, 0, 50)), subtractExtents(free, listOf(Extent(0, 50, 500), Extent(1, 0, 50))))
        assertEquals(emptyList<Extent>(), subtractExtents(free, listOf(Extent(0, 0, 1000), Extent(1, 0, 1000))))
    }

    /** The saved root of the vault, as the app's own code would read it: (container, volume, place, JSON). */
    private class SavedRoot(val seg: Segments.Segment, val volume: Int, val at: Extent, val json: JsonObject)

    private fun readRoot(s: Segments, master: ByteArray): SavedRoot {
        for (seg in s.all) {
            val v = Native.unlock(seg.handle, ContainerStorage.volumeKey(master))
            if (v < 0) continue
            val h = ByteBuffer.wrap(readVolume(seg, v, 0, ContainerStorage.HEADER_BYTES)).order(ByteOrder.LITTLE_ENDIAN)
            h.position(16)
            val at = Extent(h.int, h.long, h.long)
            if (at.n <= 0L) continue
            val sealed = readVolume(seg, v, at.o, at.n.toInt())
            val json = Json.parseToJsonElement(String(Aead.open(ContainerStorage.rootKey(master), sealed))).jsonObject
            return SavedRoot(seg, v, at, json)
        }
        error("no saved root")
    }

    private fun readVolume(seg: Segments.Segment, v: Int, offset: Long, len: Int): ByteArray {
        val out = ByteArray(len)
        var done = 0
        while (done < len) {
            val n = Native.read(seg.handle, v, offset + done, out, done, len - done)
            check(n > 0)
            done += n
        }
        return out
    }

    private fun extents(a: JsonArray?) =
        a.orEmpty().map { it.jsonObject }.map { Extent(it["s"]!!.jsonPrimitive.int, it["o"]!!.jsonPrimitive.long, it["n"]!!.jsonPrimitive.long) }

    private fun freeOf(root: JsonObject) = extents(root["free"]?.jsonArray)
    private fun filesOf(root: JsonObject) =
        root["files"]?.jsonObject.orEmpty().mapValues { extents(it.value.jsonObject["ext"]!!.jsonArray) }

    private fun overlap(a: Extent, b: Extent) = a.s == b.s && a.o < b.o + b.n && b.o < a.o + a.n

    /** Fails if the saved root calls its own place, or any byte of a file it lists, free. */
    private fun assertSavedFreeListIsSound(dir: File, master: ByteArray) {
        segs(dir).use { s ->
            val r = readRoot(s, master)
            val free = freeOf(r.json)
            val used = filesOf(r.json).values.flatten() + r.at
            for (f in free) for (u in used) assertFalse("free $f overlaps used $u", overlap(f, u))
            for (i in free.indices) for (j in 0 until i) assertFalse("free entries overlap", overlap(free[i], free[j]))
        }
    }

    @Test
    fun aRootSavedIntoFreeSpaceIsNotHandedOutAfterReopening() {
        val dir = newDir()
        val master = Aead.random(32)
        val keep = Aead.random(300_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            cs.putBytes("gone", Aead.random(900_000)); cs.putBytes("keep", keep); cs.saveIndex(byteArrayOf(1))
            cs.delete("gone")
            cs.saveIndex(byteArrayOf(2))
            // The space "gone" used is free now, so this save puts the root into it.
            cs.saveIndex(byteArrayOf(3))
            cs.close()
        }
        assertSavedFreeListIsSound(dir, master)
        val a = Aead.random(700_000); val b = Aead.random(700_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            cs.putBytes("a", a); cs.saveIndex(byteArrayOf(4))
            cs.putBytes("b", b); cs.saveIndex(byteArrayOf(5))
            assertArrayEquals(a, cs.bytes("a"))
            assertArrayEquals(b, cs.bytes("b"))
            assertArrayEquals(keep, cs.bytes("keep"))
            cs.close()
        }
        assertSavedFreeListIsSound(dir, master)
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertArrayEquals(byteArrayOf(5), cs.loadIndex())
            assertArrayEquals(a, cs.bytes("a"))
            assertArrayEquals(b, cs.bytes("b"))
            assertArrayEquals(keep, cs.bytes("keep"))
            cs.close()
        }
    }

    @Test
    fun aCrashWhileWritingAfterReopeningLeavesTheSavedRootReadable() {
        val dir = newDir()
        val master = Aead.random(32)
        val keep = Aead.random(300_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            cs.putBytes("gone", Aead.random(900_000)); cs.putBytes("keep", keep); cs.saveIndex(byteArrayOf(1))
            cs.delete("gone")
            cs.saveIndex(byteArrayOf(2)); cs.saveIndex(byteArrayOf(3))
            cs.close()
        }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            // A file is being added; something else saves the container; then the power goes.
            cs.putBytes("half", Aead.random(900_000))
            s.all.forEach { Native.flush(it.handle) }
            s.all.forEach { Native.close(it.handle) }
        }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertArrayEquals(byteArrayOf(3), cs.loadIndex())
            assertEquals(setOf("keep"), cs.names())
            assertArrayEquals(keep, cs.bytes("keep"))
            cs.close()
        }
    }

    /**
     * Writes the vault's root again the way 0.5.1 did: into the first free extent that's big
     * enough, while still listing that whole extent as free. [alsoFree] is added to the list, as
     * happened to the place of an earlier root after a file had been written over it.
     */
    private fun saveRootLikeOldVersions(dir: File, master: ByteArray, alsoFree: (Map<String, List<Extent>>) -> List<Extent>) {
        segs(dir).use { s ->
            val r = readRoot(s, master)
            val free = freeOf(r.json) + alsoFree(filesOf(r.json)) + r.at
            val json = buildJsonObject {
                r.json.forEach { (k, v) -> if (k != "free") put(k, v) }
                put("free", JsonArray(free.map { e -> buildJsonObject { put("s", e.s); put("o", e.o); put("n", e.n) } }))
            }
            val sealed = Aead.seal(ContainerStorage.rootKey(master), json.toString().toByteArray())
            // A place that really is free, as it was for 0.5.1 when it saved.
            val spot = freeOf(r.json).first { it.s == r.seg.index && it.n >= sealed.size && !overlap(it, r.at) }
            Native.write(r.seg.handle, r.volume, spot.o, sealed, 0, sealed.size)
            val header = ByteBuffer.allocate(ContainerStorage.HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
                .put("ENCLHDR1".toByteArray()).putLong(1).putInt(r.seg.index).putLong(spot.o).putLong(sealed.size.toLong()).array()
            Native.write(r.seg.handle, r.volume, 0, header, 0, header.size)
            Native.flush(r.seg.handle)
        }
    }

    @Test
    fun aVaultWhoseFreeListCoversItsRootAndFilesIsRepairedOnOpening() {
        val dir = newDir()
        val master = Aead.random(32)
        val keep = (0 until 4).associate { "k$it" to Aead.random(200_000 + it) }
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            cs.putBytes("gone", Aead.random(900_000))
            keep.forEach { (n, b) -> cs.putBytes(n, b) }
            cs.saveIndex("index".toByteArray()); cs.saveSettings("settings".toByteArray())
            cs.delete("gone")
            cs.saveIndex("index".toByteArray() + 1); cs.saveIndex("index".toByteArray())
            cs.close()
        }
        // As 0.5.1 could leave it: the root sits in space it lists as free, and so do two files.
        saveRootLikeOldVersions(dir, master) { files -> files.getValue("k1") + files.getValue("k3").map { it.copy(o = it.o + 1000, n = it.n - 1000) } }
        segs(dir).use { s ->
            val r = readRoot(s, master)
            assertTrue("the test vault is damaged", freeOf(r.json).any { overlap(it, r.at) })
        }

        val a = Aead.random(1_200_000); val b = Aead.random(1_200_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertArrayEquals("index".toByteArray(), cs.loadIndex())
            assertArrayEquals("settings".toByteArray(), cs.loadSettings())
            keep.forEach { (n, bytes) -> assertArrayEquals(n, bytes, cs.bytes(n)) }
            // Enough new data to use up everything that's really free.
            cs.putBytes("a", a); cs.saveIndex("index".toByteArray())
            cs.putBytes("b", b); cs.saveIndex("index".toByteArray())
            keep.forEach { (n, bytes) -> assertArrayEquals(n, bytes, cs.bytes(n)) }
            assertArrayEquals(a, cs.bytes("a"))
            assertArrayEquals(b, cs.bytes("b"))
            cs.close()
        }
        assertSavedFreeListIsSound(dir, master)
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertEquals(keep.keys + setOf("a", "b"), cs.names())
            keep.forEach { (n, bytes) -> assertArrayEquals(n, bytes, cs.bytes(n)) }
            assertArrayEquals(a, cs.bytes("a"))
            assertArrayEquals(b, cs.bytes("b"))
            assertArrayEquals("settings".toByteArray(), cs.loadSettings())
            cs.close()
        }
    }

    @Test
    fun aDamagedFreeListIsLeftAloneByADecoyOpenedReadOnly() {
        val dir = newDir()
        val master = Aead.random(32)
        val keep = Aead.random(200_000)
        segs(dir).use { s ->
            val cs = ContainerStorage.create(s, master, migrated = true)
            cs.putBytes("gone", Aead.random(600_000)); cs.putBytes("keep", keep); cs.saveIndex(byteArrayOf(1))
            cs.delete("gone"); cs.saveIndex(byteArrayOf(2)); cs.saveIndex(byteArrayOf(3))
            cs.close()
        }
        saveRootLikeOldVersions(dir, master) { it.getValue("keep") }
        val before = dir.listFiles()!!.sortedBy { it.name }.map { it.readBytes() }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = true)!!
            assertArrayEquals(keep, cs.bytes("keep"))
            cs.close()
        }
        val after = dir.listFiles()!!.sortedBy { it.name }.map { it.readBytes() }
        before.zip(after).forEach { (x, y) -> assertArrayEquals("opening read-only writes nothing", x, y) }
    }

    @Test
    fun manyRoundsOfChangesAndReopeningKeepEveryFile() {
        val dir = newDir()
        val master = Aead.random(32)
        val rnd = java.util.Random(20261113)
        val expect = HashMap<String, ByteArray>()
        var n = 0
        segs(dir).use { s -> ContainerStorage.create(s, master, migrated = true).close() }
        repeat(12) { session ->
            segs(dir).use { s ->
                val cs = ContainerStorage.open(s, master, readOnly = false)!!
                assertEquals(expect.keys, cs.names())
                repeat(6) {
                    when (rnd.nextInt(5)) {
                        0, 1, 2 -> { val name = "f${n++}"; val b = ByteArray(1 + rnd.nextInt(260_000)).also(rnd::nextBytes); cs.putBytes(name, b); expect[name] = b }
                        3 -> expect.keys.sorted().firstOrNull()?.let { cs.delete(it); expect.remove(it) }
                        else -> expect.keys.sorted().lastOrNull()?.let { val b = ByteArray(1 + rnd.nextInt(90_000)).also(rnd::nextBytes); cs.putBytes(it, b); expect[it] = b }
                    }
                    // Sometimes several changes go into one save, sometimes a save changes nothing but the index.
                    if (rnd.nextBoolean()) cs.saveIndex(byteArrayOf(session.toByte(), it.toByte()))
                    if (rnd.nextInt(4) == 0) cs.saveSettings(ByteArray(rnd.nextInt(3000)))
                }
                cs.saveIndex(byteArrayOf(session.toByte()))
                expect.forEach { (name, b) -> assertArrayEquals("$name in session $session", b, cs.bytes(name)) }
                cs.close()
            }
            assertSavedFreeListIsSound(dir, master)
        }
        segs(dir).use { s ->
            val cs = ContainerStorage.open(s, master, readOnly = false)!!
            assertEquals(expect.keys, cs.names())
            expect.forEach { (name, b) -> assertArrayEquals(name, b, cs.bytes(name)) }
            cs.close()
        }
    }
}
