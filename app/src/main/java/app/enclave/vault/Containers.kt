package app.enclave.vault

import app.enclave.crypto.Aead
import app.enclave.crypto.BlobSource
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * The deniable containers on this phone: equal-sized files of random-looking bytes. A vault's
 * data is spread over volumes inside them, and when they fill up another one is added, so the
 * vault keeps growing without ever moving or copying what's already stored.
 */
class Segments(val dir: File, val segmentBlocks: Long = DEFAULT_BLOCKS) : Closeable {
    class Segment(val index: Int, val handle: Long, val blocks: Long)

    private val list = mutableListOf<Segment>()

    init {
        dir.mkdirs()
        dir.listFiles().orEmpty()
            .mapNotNull { f -> f.name.toIntOrNull()?.let { it to f } }
            .sortedBy { it.first }
            .forEach { (i, f) ->
                val h = Native.open(f.path)
                list += Segment(i, h, Native.blocks(h))
            }
    }

    val all: List<Segment> @Synchronized get() = list.toList()

    fun byIndex(i: Int): Segment = all.first { it.index == i }

    /** Adds a new container, filled with random bytes. Takes a while (4 GiB of writes). */
    @Synchronized
    fun add(): Segment {
        val i = (list.maxOfOrNull { it.index } ?: -1) + 1
        val h = Native.format(File(dir, i.toString()).path, segmentBlocks)
        return Segment(i, h, segmentBlocks).also { list += it }
    }

    @Synchronized
    override fun close() {
        list.forEach { Native.close(it.handle) }
        list.clear()
    }

    companion object {
        /** 4 GiB per container. */
        const val DEFAULT_BLOCKS = 1L shl 20
    }
}

@Serializable
data class Extent(val s: Int, val o: Long, val n: Long)

@Serializable
data class StoredBlob(val size: Long, val ext: List<Extent>)

/** Everything a vault needs to find its data, sealed with a key from its master key. */
@Serializable
private data class Root(
    /** False until a vault being moved in from the old format has been fully copied and checked. */
    val migrated: Boolean = true,
    val index: String? = null,
    val settings: String? = null,
    val files: Map<String, StoredBlob> = emptyMap(),
    val free: List<Extent> = emptyList(),
)

/**
 * A vault stored in deniable containers. In each container the vault has (at most) one volume,
 * opened by a key derived from the vault's master key; nothing outside says it exists. The
 * volume's first bytes hold a small header, and in the vault's home volume that header points to
 * the sealed [Root]. Blobs are byte ranges ([Extent]s) of the volumes.
 *
 * Saving is crash-safe: new data goes only into space no saved root uses, the other containers
 * are flushed first, then the new root and header are written and the home container flushed,
 * which the crate does atomically. Space given up is only reused once a saved root stops using it.
 */
class ContainerStorage private constructor(
    private val segs: Segments,
    volKey: ByteArray,
    rootKey: ByteArray,
    override val readOnly: Boolean,
) : Storage {
    private val volKey = volKey.copyOf()
    private val rootKey = rootKey.copyOf()
    private val json = Json { ignoreUnknownKeys = true }

    /** Container index -> this vault's volume in it. */
    private val vol = ConcurrentHashMap<Int, Int>()
    /** Container index -> where this vault's volume currently ends. */
    private val ends = ConcurrentHashMap<Int, Long>()
    /** Container index -> volumes of other vaults (decoys) kept open so their space is respected. */
    private val others = HashMap<Int, MutableList<Int>>()
    private val protectedKeys = mutableListOf<ByteArray>()
    private val unflushed = ConcurrentHashMap<Int, Long>()
    private val full = HashSet<Int>()

    private var home = -1
    private var gen = 0L
    private var rootExtent: Extent? = null
    private var migratedFlag = true
    private var index: ByteArray? = null
    private var settings: ByteArray? = null
    private val files = HashMap<String, StoredBlob>()
    private val free = mutableListOf<Extent>()
    private val pending = mutableListOf<Extent>()
    private var dirty = false
    @Volatile private var closed = false

    val migrated: Boolean @Synchronized get() = migratedFlag

    // ---- Reading and writing a volume ---------------------------------------------------

    private fun handle(seg: Int) = segs.byIndex(seg).handle

    private fun volRead(seg: Int, offset: Long, dst: ByteArray, off: Int, len: Int): Int =
        Native.read(handle(seg), vol.getValue(seg), offset, dst, off, len)

    private fun volReadFully(seg: Int, offset: Long, len: Int): ByteArray {
        val out = ByteArray(len)
        var done = 0
        while (done < len) {
            val n = volRead(seg, offset + done, out, done, len - done)
            if (n <= 0) throw IOException("vault data ended early")
            done += n
        }
        return out
    }

    private fun volWrite(seg: Int, offset: Long, src: ByteArray, off: Int, len: Int) {
        Native.write(handle(seg), vol.getValue(seg), offset, src, off, len)
        unflushed.merge(seg, len.toLong(), Long::plus)
    }

    private fun header(gen: Long, root: Extent?): ByteArray =
        ByteBuffer.allocate(HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
            .put(MAGIC).putLong(gen).putInt(root?.s ?: 0).putLong(root?.o ?: 0).putLong(root?.n ?: 0).array()

    // ---- Space -----------------------------------------------------------------------------

    private fun blocksFor(bytes: Long) = (bytes + Native.PAYLOAD - 1) / Native.PAYLOAD

    /** How far this vault's volume in [seg] may grow, leaving room for the crate's own needs. */
    private fun limit(seg: Int): Long {
        val s = segs.byIndex(seg)
        val otherBytes = others[seg].orEmpty().sumOf { v -> Native.len(s.handle, v).coerceAtLeast(0) }
        val mine = blocksFor(ends[seg] ?: 0)
        val theirs = blocksFor(otherBytes)
        val maps = (mine + theirs) / 1011 * 2 + 8 * (1 + others[seg].orEmpty().size)
        val reserve = s.blocks / 100 + maps + blocksFor(unflushed[seg] ?: 0) + 64
        val room = s.blocks - 1 - reserve - theirs
        val limit = room * Native.PAYLOAD
        // The home container keeps space for the root, whatever happens.
        return if (seg == home) limit - minOf(HOME_RESERVE, s.blocks * Native.PAYLOAD / 8) else limit
    }

    private fun addFree(e: Extent) {
        if (e.n <= 0) return
        free += e
        free.sortWith(compareBy({ it.s }, { it.o }))
        var i = 0
        while (i < free.size - 1) {
            val a = free[i]; val b = free[i + 1]
            if (a.s == b.s && a.o + a.n == b.o) {
                free[i] = a.copy(n = a.n + b.n); free.removeAt(i + 1)
            } else i++
        }
    }

    /** Gives back the unused tail of an extent that nothing references yet. */
    private fun giveBack(e: Extent) {
        if (e.n <= 0) return
        if (ends[e.s] == e.o + e.n) ends[e.s] = e.o else addFree(e)
    }

    /** Space for the next piece of a blob: reused free space first, then the end of a volume. */
    @Synchronized
    private fun nextExtent(want: Long): Extent {
        check(!closed) { "vault is locked" }
        if (readOnly) throw StorageFullException()
        free.firstOrNull { it.s !in full }?.let { e ->
            free.remove(e)
            if (e.n > want) {
                free += e.copy(o = e.o + want, n = e.n - want)
                return e.copy(n = want)
            }
            return e
        }
        for (s in segs.all.map { it.index }) {
            if (s in full || !vol.containsKey(s)) continue
            val end = ends.getValue(s)
            val room = limit(s) - end
            if (room >= minOf(want, MIN_EXTENT)) {
                val n = minOf(want, room)
                ends[s] = end + n
                return Extent(s, end, n)
            }
        }
        addContainer()
        return nextExtent(want)
    }

    /** Grows the vault: a new container, with a volume for this vault in it. */
    private fun addContainer() {
        val s = segs.add()
        joinContainer(s)
    }

    private fun joinContainer(s: Segments.Segment) {
        val v = Native.create(s.handle, volKey)
        vol[s.index] = v
        Native.write(s.handle, v, 0, header(0, null), 0, HEADER_BYTES)
        ends[s.index] = DATA_START
        unflushed[s.index] = HEADER_BYTES.toLong()
        protectedKeys.forEach { k -> Native.unlock(s.handle, k).takeIf { it >= 0 }?.let { others.getOrPut(s.index) { mutableListOf() } += it } }
        dirty = true
    }

    private inner class ExtentOutput : OutputStream() {
        val extents = mutableListOf<Extent>()
        var size = 0L
        private var cur: Extent? = null
        private var used = 0L
        private val buf = ByteArray(64 * 1024)
        private var fill = 0

        override fun write(b: Int) {
            if (fill == buf.size) drain()
            buf[fill++] = b.toByte()
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            var o = off; var left = len
            while (left > 0) {
                if (fill == buf.size) drain()
                val n = minOf(left, buf.size - fill)
                System.arraycopy(b, o, buf, fill, n)
                fill += n; o += n; left -= n
            }
        }

        private fun drain() {
            var o = 0
            while (o < fill) {
                var c = cur
                if (c == null || used == c.n) {
                    c = nextExtent(CHUNK)
                    cur = c; used = 0
                    extents += c
                }
                val n = minOf((fill - o).toLong(), c.n - used).toInt()
                try {
                    volWrite(c.s, c.o + used, buf, o, n)
                } catch (e: IOException) {
                    if (e.message != Native.FULL) throw e
                    // The crate ran out of room before the estimate did: stop using this container.
                    synchronized(this@ContainerStorage) {
                        full += c.s
                        giveBack(c.copy(o = c.o + used, n = c.n - used))
                    }
                    extents[extents.lastIndex] = c.copy(n = used)
                    cur = null
                    continue
                }
                used += n; o += n; size += n
            }
            buf.fill(0, 0, fill)
            fill = 0
        }

        fun finish() {
            drain()
            val c = cur ?: return
            if (used < c.n) {
                synchronized(this@ContainerStorage) { giveBack(c.copy(o = c.o + used, n = c.n - used)) }
                extents[extents.lastIndex] = c.copy(n = used)
            }
            extents.removeAll { it.n == 0L }
        }
    }

    private inner class ExtentSource(private val blob: StoredBlob) : BlobSource {
        override val length = blob.size

        override fun read(position: Long, dst: ByteArray, off: Int, len: Int): Int {
            if (position >= length) return -1
            var skip = position
            for (e in blob.ext) {
                if (skip >= e.n) { skip -= e.n; continue }
                val n = minOf(len.toLong(), e.n - skip, length - position).toInt()
                return volRead(e.s, e.o + skip, dst, off, n)
            }
            return -1
        }
    }

    // ---- Storage ---------------------------------------------------------------------------

    override fun loadIndex(): ByteArray? = synchronized(this) { index?.copyOf() }
    override fun loadSettings(): ByteArray? = synchronized(this) { settings?.copyOf() }

    override fun saveIndex(sealed: ByteArray) {
        if (readOnly) throw StorageFullException()
        synchronized(this) { index = sealed.copyOf(); dirty = true }
        commit()
    }

    override fun saveSettings(sealed: ByteArray) {
        synchronized(this) { settings = sealed.copyOf(); dirty = true }
        // A read-only decoy keeps settings for this session only.
        if (!readOnly) commit()
    }

    override fun names(): Set<String> = synchronized(this) { files.keys.toSet() }
    override fun size(name: String): Long = synchronized(this) { files[name]?.size ?: -1 }

    override fun open(name: String): BlobSource {
        val b = synchronized(this) { files[name] } ?: throw IOException("no such file")
        return ExtentSource(b)
    }

    override fun put(name: String, write: (OutputStream) -> Unit) {
        if (readOnly) throw StorageFullException()
        val out = ExtentOutput()
        try {
            write(out)
            out.finish()
        } catch (t: Throwable) {
            synchronized(this) { out.extents.forEach(::giveBack) }
            throw t
        }
        synchronized(this) {
            check(!closed) { "vault is locked" }
            files.put(name, StoredBlob(out.size, out.extents.toList()))?.let { pending += it.ext }
            dirty = true
        }
    }

    override fun delete(name: String) {
        if (readOnly) throw StorageFullException()
        synchronized(this) {
            files.remove(name)?.let { pending += it.ext; dirty = true }
        }
    }

    @Synchronized
    override fun commit() {
        if (readOnly || !dirty || closed) return
        // 1. Everything the new root will point to goes to the disk first.
        for (s in vol.keys) if (s != home && (unflushed[s] ?: 0) > 0) {
            Native.flush(handle(s)); unflushed[s] = 0
        }
        // 2. The new root, into space no saved root uses, in the home volume.
        val old = rootExtent
        val persistedFree = (free + pending + listOfNotNull(old))
        val root = Root(
            migrated = migratedFlag,
            index = index?.let { Base64.getEncoder().encodeToString(it) },
            settings = settings?.let { Base64.getEncoder().encodeToString(it) },
            files = files.toMap(),
            free = persistedFree,
        )
        val sealed = Aead.seal(rootKey, json.encodeToString(root).toByteArray())
        val need = sealed.size.toLong()
        val spot = free.firstOrNull { it.s == home && it.n >= need }
        val at = if (spot != null) {
            free.remove(spot)
            if (spot.n > need) free += spot.copy(o = spot.o + need, n = spot.n - need)
            Extent(home, spot.o, need)
        } else {
            val end = ends.getValue(home)
            ends[home] = end + need
            Extent(home, end, need)
        }
        volWrite(home, at.o, sealed, 0, sealed.size)
        volWrite(home, 0, header(gen + 1, at), 0, HEADER_BYTES)
        // 3. The crate saves the home volume atomically: the old root stays valid until now.
        Native.flush(handle(home))
        unflushed[home] = 0
        gen += 1
        rootExtent = at
        pending.forEach(::addFree)
        pending.clear()
        old?.let(::addFree)
        dirty = false
    }

    /** Marks a vault moved in from the old format as complete. */
    fun finishMigration() {
        synchronized(this) { migratedFlag = true; dirty = true }
        commit()
    }

    /** Keeps other vaults' volumes (decoys) open so this vault never writes over them. */
    @Synchronized
    fun protect(key: ByteArray) {
        if (protectedKeys.any { it.contentEquals(key) }) return
        protectedKeys += key.copyOf()
        for (s in segs.all) Native.unlock(s.handle, key).takeIf { it >= 0 }?.let { others.getOrPut(s.index) { mutableListOf() } += it }
    }

    /** Bytes this vault occupies, and the total size of its containers. */
    @Synchronized
    fun usage(): Pair<Long, Long> =
        ends.values.sum() to segs.all.filter { vol.containsKey(it.index) }.sumOf { it.blocks * Native.PAYLOAD }

    override fun close() {
        synchronized(this) {
            if (closed) return
            runCatching { commit() }
            closed = true
            volKey.fill(0); rootKey.fill(0)
            protectedKeys.forEach { it.fill(0) }
            index?.fill(0); settings?.fill(0)
        }
    }

    companion object {
        private val MAGIC = "ENCLHDR1".toByteArray()
        const val HEADER_BYTES = 36
        /** The volume's first bytes hold the header; data starts after one full block of payload. */
        private const val DATA_START = 4096L
        private const val CHUNK = 8L * 1024 * 1024
        private const val MIN_EXTENT = 64L * 1024
        private const val HOME_RESERVE = 32L * 1024 * 1024

        fun volumeKey(master: ByteArray) = Aead.subkey(master, "deniable volume")
        fun rootKey(master: ByteArray) = Aead.subkey(master, "container root")

        /** Opens the vault with this master key, or returns null if it has no container volume. */
        fun open(segs: Segments, master: ByteArray, readOnly: Boolean): ContainerStorage? {
            val cs = ContainerStorage(segs, volumeKey(master), rootKey(master), readOnly)
            var best: Triple<Int, Long, Extent>? = null
            for (s in segs.all) {
                val v = Native.unlock(s.handle, cs.volKey)
                if (v < 0) continue
                cs.vol[s.index] = v
                cs.ends[s.index] = maxOf(Native.len(s.handle, v), DATA_START)
                val h = ByteBuffer.wrap(cs.volReadFully(s.index, 0, HEADER_BYTES)).order(ByteOrder.LITTLE_ENDIAN)
                val magic = ByteArray(8).also { h.get(it) }
                if (!magic.contentEquals(MAGIC)) continue
                val gen = h.long
                val root = Extent(h.int, h.long, h.long)
                if (root.n > 0 && (best == null || gen > best.second)) best = Triple(s.index, gen, root)
            }
            val (home, gen, rootAt) = best ?: return null.also { cs.wipeKeys() }
            cs.home = home
            cs.gen = gen
            cs.rootExtent = rootAt
            val sealed = cs.volReadFully(rootAt.s, rootAt.o, rootAt.n.toInt())
            val root = cs.json.decodeFromString<Root>(String(Aead.open(cs.rootKey, sealed)))
            cs.migratedFlag = root.migrated
            cs.index = root.index?.let { Base64.getDecoder().decode(it) }
            cs.settings = root.settings?.let { Base64.getDecoder().decode(it) }
            cs.files.putAll(root.files)
            root.free.forEach(cs::addFree)
            return cs
        }

        /**
         * Makes a new, empty vault in the containers (adding the first container if there's none).
         * [migrated] = false while a vault is being moved in from the old format.
         */
        fun create(segs: Segments, master: ByteArray, migrated: Boolean): ContainerStorage {
            val cs = ContainerStorage(segs, volumeKey(master), rootKey(master), readOnly = false)
            val s = segs.all.firstOrNull() ?: segs.add()
            cs.joinContainer(s)
            cs.home = s.index
            cs.migratedFlag = migrated
            cs.dirty = true
            cs.commit()
            return cs
        }

        /** Destroys a vault's volumes in every container (removing a decoy). */
        fun destroy(segs: Segments, master: ByteArray) {
            val key = volumeKey(master)
            for (s in segs.all) {
                val v = Native.unlock(s.handle, key)
                if (v >= 0) {
                    Native.destroy(s.handle, v)
                    Native.flush(s.handle)
                }
            }
            key.fill(0)
        }
    }

    private fun wipeKeys() {
        volKey.fill(0); rootKey.fill(0)
    }
}
