package app.enclave

import app.enclave.crypto.Scrub
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32

/** What a shared copy of a photo or video no longer says (see Scrub). */
class ScrubTest {
    private fun scrubbed(file: ByteArray): ByteArray {
        val src = Scrub.Source { offset, buf, off, len ->
            val n = minOf(len.toLong(), file.size - offset).toInt()
            if (n <= 0) -1 else n.also { System.arraycopy(file, offset.toInt(), buf, off, n) }
        }
        val patches = Scrub.patches(src, file.size.toLong())
        val whole = file.copyOf()
        Scrub.apply(patches, 0, whole, whole.size)
        // Read in small pieces from odd positions, as another app might: the same bytes.
        val pieces = ByteArray(file.size)
        var at = 0
        while (at < file.size) {
            val n = minOf(7, file.size - at)
            val part = file.copyOfRange(at, at + n)
            Scrub.apply(patches, at.toLong(), part, n)
            part.copyInto(pieces, at)
            at += n
        }
        assertArrayEquals(whole, pieces)
        assertEquals(file.size, whole.size)
        return whole
    }

    private fun has(b: ByteArray, s: String) = String(b, Charsets.ISO_8859_1).contains(s)
    private fun be16(v: Int) = byteArrayOf((v shr 8).toByte(), v.toByte())
    private fun be32(v: Int) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())
    private fun join(vararg parts: ByteArray) = ByteArrayOutputStream().also { o -> parts.forEach(o::write) }.toByteArray()
    private fun seg(marker: Int, payload: ByteArray) = join(byteArrayOf(0xFF.toByte(), marker.toByte()), be16(payload.size + 2), payload)

    /** Little-endian Exif: orientation, then a made-up maker string and GPS text after it. */
    private fun exif(orientation: Int): ByteArray = join(
        "Exif\u0000\u0000II".toByteArray(Charsets.ISO_8859_1), byteArrayOf(42, 0, 8, 0, 0, 0),
        byteArrayOf(2, 0),
        byteArrayOf(0x0F, 0x01, 2, 0, 9, 0, 0, 0, 38, 0, 0, 0),
        byteArrayOf(0x12, 0x01, 3, 0, 1, 0, 0, 0, orientation.toByte(), 0, 0, 0),
        byteArrayOf(0, 0, 0, 0),
        "PhoneMake GPS 52.5200N 13.4050E".toByteArray(),
    )

    private val picture = byteArrayOf(0xFF.toByte(), 0xDA.toByte(), 0, 2, 1, 2, 3, 4, 0xFF.toByte(), 0xD9.toByte())

    private fun jpeg(orientation: Int) = join(
        byteArrayOf(0xFF.toByte(), 0xD8.toByte()),
        seg(0xE0, "JFIF\u0000".toByteArray(Charsets.ISO_8859_1)),
        seg(0xE1, exif(orientation)),
        seg(0xE1, "http://ns.adobe.com/xap/1.0/\u0000<x:xmpmeta>Secret Place</x:xmpmeta>".toByteArray(Charsets.ISO_8859_1)),
        seg(0xE2, "ICC_PROFILE\u0000colour".toByteArray(Charsets.ISO_8859_1)),
        seg(0xED, "Photoshop 3.0 caption".toByteArray()),
        seg(0xFE, "shot on my phone".toByteArray()),
        picture,
    )

    @Test
    fun aJpegLosesItsPositionAndCameraButStaysTurned() {
        val out = scrubbed(jpeg(orientation = 6))
        for (gone in listOf("PhoneMake", "52.5200N", "Secret Place", "xmpmeta", "caption", "shot on my phone")) assertFalse(gone, has(out, gone))
        assertTrue(has(out, "JFIF"))
        assertTrue(has(out, "ICC_PROFILE\u0000colour"))
        // The Exif block that's left: big-endian, one entry, orientation 6.
        val at = String(out, Charsets.ISO_8859_1).indexOf("Exif\u0000\u0000MM")
        assertTrue(at > 0)
        assertArrayEquals(byteArrayOf(0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6), out.copyOfRange(at + 14, at + 26))
        assertArrayEquals(picture, out.copyOfRange(out.size - picture.size, out.size))
    }

    @Test
    fun anUprightJpegKeepsNoExifAtAll() {
        val out = scrubbed(jpeg(orientation = 1))
        assertFalse(has(out, "Exif"))
        assertFalse(has(out, "PhoneMake"))
    }

    private fun chunk(type: String, data: ByteArray): ByteArray {
        val body = join(type.toByteArray(Charsets.ISO_8859_1), data)
        return join(be32(data.size), body, be32(CRC32().apply { update(body) }.value.toInt()))
    }

    @Test
    fun aPngLosesItsTextAndKeepsValidChunks() {
        val sig = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(), 13, 10, 26, 10)
        val idat = chunk("IDAT", byteArrayOf(9, 8, 7, 6, 5))
        val file = join(sig, chunk("IHDR", ByteArray(13)), chunk("tEXt", "Software\u0000MyPhone Camera".toByteArray(Charsets.ISO_8859_1)), idat,
            chunk("eXIf", "GPS here".toByteArray()), chunk("IEND", ByteArray(0)))
        val out = scrubbed(file)
        assertFalse(has(out, "MyPhone"))
        assertFalse(has(out, "GPS here"))
        assertFalse(has(out, "tEXt"))
        assertTrue(has(out, "IDAT"))
        // Every chunk's checksum still matches.
        var p = 8
        while (p < out.size) {
            val len = java.nio.ByteBuffer.wrap(out, p, 4).int
            val crc = CRC32().apply { update(out, p + 4, len + 4) }.value.toInt()
            assertEquals(crc, java.nio.ByteBuffer.wrap(out, p + 8 + len, 4).int)
            p += 12 + len
        }
    }

    private fun box(type: String, vararg inside: ByteArray): ByteArray {
        val body = join(*inside)
        return join(be32(body.size + 8), type.toByteArray(Charsets.ISO_8859_1), body)
    }

    @Test
    fun aVideoLosesWhereItWasShot() {
        val mdat = box("mdat", "the frames".toByteArray())
        val file = join(
            box("ftyp", "isom".toByteArray(), ByteArray(4)),
            mdat,
            box("moov",
                box("mvhd", ByteArray(20)),
                box("trak", box("tkhd", ByteArray(12)), box("udta", "track note".toByteArray())),
                box("udta", box("©xyz", "+52.5200+013.4050/".toByteArray())),
                box("meta", "com.android.manufacturer PhoneMake".toByteArray()),
            ),
        )
        val out = scrubbed(file)
        for (gone in listOf("+52.5200", "PhoneMake", "track note", "udta", "meta")) assertFalse(gone, has(out, gone))
        for (kept in listOf("the frames", "mvhd", "tkhd", "trak", "moov")) assertTrue(kept, has(out, kept))
        assertEquals(3, String(out, Charsets.ISO_8859_1).windowed(4).count { it == "free" })
    }

    @Test
    fun otherFilesAreLeftAlone() {
        val pdf = "%PDF-1.7 some text udta meta Exif".toByteArray()
        assertArrayEquals(pdf, scrubbed(pdf))
        val song = join(box("ftyp", "M4A ".toByteArray(), ByteArray(4)), box("moov", box("udta", "Song title".toByteArray())))
        assertArrayEquals(song, scrubbed(song))
        assertArrayEquals(ByteArray(3), scrubbed(ByteArray(3)))
        // Cut off in the middle of a header: nothing breaks.
        scrubbed(jpeg(6).copyOf(40))
    }
}
