package app.enclave.vault

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ImageDecoder
import android.media.MediaDataSource
import android.media.MediaMetadataRetriever
import android.media.ThumbnailUtils
import android.util.Size
import app.enclave.crypto.ChunkedCipher
import java.io.File
import java.nio.ByteBuffer

/** Lets Android's media code (thumbnails, video frames) read an encrypted file without a plaintext copy. */
class EncryptedMediaSource(private val reader: ChunkedCipher.Reader) : MediaDataSource() {
    override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int) = reader.read(position, buffer, offset, size)
    override fun getSize() = reader.size
    override fun close() = reader.close()
}

object Media {
    const val THUMB = 256
    private const val MAX_IN_MEMORY = 40L * 1024 * 1024

    /** The file's type, falling back to its extension when the type wasn't known at import. */
    fun mimeOf(e: Entry): String {
        if (e.mime != "application/octet-stream") return e.mime
        val ext = e.name.substringAfterLast('.', "").lowercase()
        return android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: e.mime
    }

    fun isImage(e: Entry) = mimeOf(e).startsWith("image/")
    fun isVideo(e: Entry) = mimeOf(e).startsWith("video/")
    fun isAudio(e: Entry) = mimeOf(e).startsWith("audio/")
    fun isText(e: Entry) = mimeOf(e).let { it.startsWith("text/") || it == "application/json" }
    fun mayAnimate(e: Entry) = mimeOf(e).let { it == "image/gif" || it == "image/webp" || it == "image/apng" || it == "image/png" }

    /** Opens inside Enclave's own viewer rather than another app. */
    fun isViewable(e: Entry) = isImage(e) || isVideo(e) || isAudio(e) || isText(e)

    /** Reads a whole file into memory (for small media such as GIFs). Caller should wipe it. */
    fun readAll(store: VaultStore, e: Entry): ByteArray =
        store.reader(e).use { r -> ByteArray(r.size.toInt()).also { r.read(0, it, 0, it.size) } }

    /**
     * Decodes an image, honouring its EXIF rotation, scaled so its longest side is about [maxSide].
     * Everything happens in memory.
     */
    fun decodeImage(store: VaultStore, e: Entry, maxSide: Int): Bitmap? {
        if (e.size <= MAX_IN_MEMORY) {
            val bytes = store.reader(e).use { r -> ByteArray(r.size.toInt()).also { r.read(0, it, 0, it.size) } }
            try {
                return ImageDecoder.decodeBitmap(ImageDecoder.createSource(ByteBuffer.wrap(bytes))) { dec, info, _ ->
                    val longest = maxOf(info.size.width, info.size.height)
                    if (longest > maxSide) dec.setTargetSampleSize(longest / maxSide)
                    dec.allocator = ImageDecoder.ALLOCATOR_SOFTWARE
                }
            } catch (_: Exception) {
                // Fall through to BitmapFactory for formats ImageDecoder rejects.
            } finally {
                bytes.fill(0)
            }
        }
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        store.reader(e).use { BitmapFactory.decodeStream(it.inputStream(), null, bounds) }
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= maxSide) sample *= 2
        return store.reader(e).use {
            BitmapFactory.decodeStream(it.inputStream(), null, BitmapFactory.Options().apply { inSampleSize = sample })
        }
    }

    /** A file's type from its name alone, for files outside the vault. */
    fun mimeOfName(name: String): String =
        android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(name.substringAfterLast('.', "").lowercase())
            ?: "application/octet-stream"

    /**
     * A preview of a file outside the vault (for the built-in folder browser), made in memory.
     * Nothing is written anywhere and Android's media index isn't asked, so browsing leaves no
     * thumbnails behind on the phone.
     */
    fun makeThumbnail(f: File): Bitmap? {
        val mime = mimeOfName(f.name)
        val size = Size(THUMB, THUMB)
        return runCatching {
            when {
                mime.startsWith("image/") -> ThumbnailUtils.createImageThumbnail(f, size, null)
                mime.startsWith("video/") -> ThumbnailUtils.createVideoThumbnail(f, size, null)
                else -> null
            }
        }.getOrNull()
    }

    fun makeThumbnail(store: VaultStore, e: Entry): Bitmap? = when {
        isImage(e) -> decodeImage(store, e, THUMB * 2)?.let { ThumbnailUtils.extractThumbnail(it, THUMB, THUMB) }
        isVideo(e) -> MediaMetadataRetriever().run {
            try {
                setDataSource(EncryptedMediaSource(store.reader(e)))
                getScaledFrameAtTime(1_000_000, MediaMetadataRetriever.OPTION_CLOSEST_SYNC, THUMB * 2, THUMB * 2)
                    ?.let { ThumbnailUtils.extractThumbnail(it, THUMB, THUMB) }
            } finally {
                release()
            }
        }
        else -> null
    }
}
