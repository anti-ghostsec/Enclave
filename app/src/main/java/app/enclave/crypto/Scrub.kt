package app.enclave.crypto

import java.util.zip.CRC32

/**
 * Takes what a photo or video says about where and with what it was made out of the copy another
 * app is given: GPS position, camera make and model, software, dates, comments, embedded
 * previews. The file in the vault is never changed.
 *
 * Nothing is cut out, only written over, so the file keeps its length and every other byte stays
 * where it was: a link can still be read from any position, straight from the vault, with these
 * few ranges swapped in. Covers JPEG (Exif, XMP, IPTC, comments, maker segments; the rotation is
 * kept), PNG (text, Exif and time chunks) and MP4/MOV video (the "udta" and "meta" boxes of the
 * movie and its tracks, where phones put the location). Other formats pass through as they are:
 * see the README's known limits.
 */
object Scrub {
    class Patch(val offset: Long, val bytes: ByteArray)

    fun interface Source {
        /** Reads up to [len] bytes at [offset]; fewer only at the end. */
        fun read(offset: Long, buf: ByteArray, off: Int, len: Int): Int
    }

    /** What to write over in a file of [size] bytes; empty for a format this doesn't know. */
    fun patches(src: Source, size: Long): List<Patch> = runCatching {
        val head = at(src, 0, 12, size) ?: return emptyList()
        when {
            u8(head, 0) == 0xFF && u8(head, 1) == 0xD8 -> jpeg(src, size)
            head.copyOf(8).contentEquals(PNG) -> png(src, size)
            String(head, 4, 4, Charsets.ISO_8859_1) == "ftyp" && String(head, 8, 4, Charsets.ISO_8859_1) != "M4A " -> mp4(src, size)
            else -> emptyList()
        }
    }.getOrDefault(emptyList())

    /** Writes the patches over [data], which holds [len] bytes read at [offset]. */
    fun apply(patches: List<Patch>, offset: Long, data: ByteArray, len: Int) {
        for (p in patches) {
            val from = maxOf(p.offset, offset)
            val to = minOf(p.offset + p.bytes.size, offset + len)
            if (from < to) System.arraycopy(p.bytes, (from - p.offset).toInt(), data, (from - offset).toInt(), (to - from).toInt())
        }
    }

    private val PNG = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(), 13, 10, 26, 10)
    private const val MAX_STEPS = 20_000
    private const val MAX_MOOV = 32L * 1024 * 1024

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun u32(b: ByteArray, i: Int) = (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()

    /** Exactly [n] bytes at [offset], or null if the file ends first. */
    private fun at(src: Source, offset: Long, n: Int, size: Long): ByteArray? {
        if (offset < 0 || n < 0 || offset + n > size) return null
        val b = ByteArray(n)
        var got = 0
        while (got < n) {
            val r = src.read(offset + got, b, got, n - got)
            if (r <= 0) return null
            got += r
        }
        return b
    }

    // ---- JPEG -------------------------------------------------------------------------------

    private fun jpeg(src: Source, size: Long): List<Patch> {
        val out = ArrayList<Patch>()
        var pos = 2L
        repeat(MAX_STEPS) {
            val h = at(src, pos, 4, size) ?: return out
            if (u8(h, 0) != 0xFF) return out
            val marker = u8(h, 1)
            // The picture itself starts (or the file ends): nothing after this is a header.
            if (marker == 0xDA || marker == 0xD9) return out
            if (marker == 0xFF) { pos += 1; return@repeat }
            if (marker == 0x01 || marker in 0xD0..0xD7) { pos += 2; return@repeat }
            val len = u16(h, 2)
            if (len < 2) return out
            // Kept: JFIF (E0), colour profiles and multi-picture data (E2), Adobe's colour
            // transform (EE). Everything else an app can put there goes.
            val drop = marker == 0xFE || (marker in 0xE1..0xEF && marker != 0xE2 && marker != 0xEE)
            if (drop) {
                val payload = at(src, pos + 4, len - 2, size) ?: return out
                val keep = if (marker == 0xE1) rotationOnly(payload) else null
                val seg = ByteArray(len + 2)
                seg[0] = 0xFF.toByte()
                seg[1] = (if (keep != null) 0xE1 else 0xFE).toByte()
                seg[2] = h[2]; seg[3] = h[3]
                keep?.copyInto(seg, 4)
                out += Patch(pos, seg)
            }
            pos += 2 + len
        }
        return out
    }

    /**
     * An Exif block of the same length that says how the picture is turned and nothing else, or
     * null if this isn't Exif or the picture isn't turned. Without it a phone photo taken
     * upright would arrive lying on its side.
     */
    private fun rotationOnly(payload: ByteArray): ByteArray? {
        if (payload.size < 32 || String(payload, 0, 6, Charsets.ISO_8859_1) != "Exif\u0000\u0000") return null
        val t = 6
        val little = when (String(payload, t, 2, Charsets.ISO_8859_1)) { "II" -> true; "MM" -> false; else -> return null }
        fun r16(i: Int) = if (little) u8(payload, i) or (u8(payload, i + 1) shl 8) else u16(payload, i)
        fun r32(i: Int) = if (little) r16(i).toLong() or (r16(i + 2).toLong() shl 16) else (r16(i).toLong() shl 16) or r16(i + 2).toLong()
        if (t + 8 > payload.size) return null
        val ifd = t + r32(t + 4)
        if (ifd < t + 8 || ifd + 2 > payload.size) return null
        val entries = r16(ifd.toInt())
        var turned = 0
        for (i in 0 until entries) {
            val e = ifd.toInt() + 2 + i * 12
            if (e + 12 > payload.size) break
            if (r16(e) == 0x0112) turned = r16(e + 8)
        }
        if (turned !in 2..8) return null
        val out = ByteArray(payload.size)
        byteArrayOf(
            'E'.code.toByte(), 'x'.code.toByte(), 'i'.code.toByte(), 'f'.code.toByte(), 0, 0,
            'M'.code.toByte(), 'M'.code.toByte(), 0, 42, 0, 0, 0, 8,
            0, 1, // one entry
            0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, turned.toByte(), 0, 0,
            0, 0, 0, 0, // no further directory
        ).copyInto(out)
        return out
    }

    // ---- PNG --------------------------------------------------------------------------------

    private val PNG_DROP = setOf("tEXt", "zTXt", "iTXt", "eXIf", "tIME")
    /** An ancillary, private chunk readers skip: what a dropped chunk becomes. */
    private val PNG_BLANK = "zzZz".toByteArray(Charsets.ISO_8859_1)

    private fun png(src: Source, size: Long): List<Patch> {
        val out = ArrayList<Patch>()
        var pos = 8L
        repeat(MAX_STEPS) {
            val h = at(src, pos, 8, size) ?: return out
            val len = u32(h, 0)
            val type = String(h, 4, 4, Charsets.ISO_8859_1)
            if (type == "IEND") return out
            if (type in PNG_DROP && len <= 4 * 1024 * 1024 && pos + 12 + len <= size) {
                val blank = ByteArray(len.toInt() + 8)
                PNG_BLANK.copyInto(blank)
                val crc = CRC32().apply { update(blank, 0, blank.size - 4) }.value
                for (i in 0 until 4) blank[blank.size - 4 + i] = (crc shr (24 - 8 * i)).toByte()
                out += Patch(pos + 4, blank)
            }
            pos += 12 + len
        }
        return out
    }

    // ---- MP4 / MOV --------------------------------------------------------------------------

    private val FREE = "free".toByteArray(Charsets.ISO_8859_1)

    private fun mp4(src: Source, size: Long): List<Patch> {
        val out = ArrayList<Patch>()
        var pos = 0L
        repeat(MAX_STEPS) {
            val h = at(src, pos, 8, size) ?: return out
            var box = u32(h, 0)
            var header = 8
            if (box == 1L) {
                val big = at(src, pos + 8, 8, size) ?: return out
                box = (u32(big, 0) shl 32) or u32(big, 4)
                header = 16
            } else if (box == 0L) box = size - pos
            if (box < header || pos + box > size) return out
            if (String(h, 4, 4, Charsets.ISO_8859_1) == "moov" && box <= MAX_MOOV) {
                val moov = at(src, pos, box.toInt(), size) ?: return out
                blankIn(moov, header, moov.size, pos, out, depth = 0)
            }
            pos += box
        }
        return out
    }

    /**
     * Turns every "udta" and "meta" box directly inside [from, to) into free space, and looks
     * inside the tracks for more. Phones keep the place a video was shot, their own model and
     * their software's name in those.
     */
    private fun blankIn(b: ByteArray, from: Int, to: Int, base: Long, out: MutableList<Patch>, depth: Int) {
        var p = from
        while (p + 8 <= to) {
            val box = u32(b, p)
            if (box < 8 || p + box > to) return
            val end = p + box.toInt()
            when (String(b, p + 4, 4, Charsets.ISO_8859_1)) {
                "udta", "meta" -> {
                    val blank = ByteArray(box.toInt() - 4)
                    FREE.copyInto(blank)
                    out += Patch(base + p + 4, blank)
                }
                "trak" -> if (depth == 0) blankIn(b, p + 8, end, base, out, depth + 1)
            }
            p = end
        }
    }
}
