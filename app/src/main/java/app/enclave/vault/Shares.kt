package app.enclave.vault

import android.content.Context
import android.net.Uri
import app.enclave.crypto.Aead
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Files you hand to another app (a video player, a forum's upload button, the share sheet).
 *
 * Each share holds only that one file's key, so it keeps working after Enclave auto-locks (the
 * player can keep playing, the browser can finish uploading) without keeping the vault itself
 * open. Shares end when the screen turns off, after [LIFETIME_MS], or with [clear].
 */
object Shares {
    const val LIFETIME_MS = 30 * 60 * 1000L

    class Share(val blob: File, val key: ByteArray, val name: String, val mime: String, val size: Long, val expires: Long)

    private val live = ConcurrentHashMap<String, Share>()

    fun create(context: Context, store: VaultStore, e: Entry): Uri {
        val token = Aead.hex(Aead.random(16))
        live[token] = Share(store.blobOf(e), store.keyBytes(e), e.name, e.mime, e.size, System.currentTimeMillis() + LIFETIME_MS)
        return Uri.parse("content://${context.packageName}.files/$token/${Uri.encode(e.name)}")
    }

    fun get(uri: Uri): Share? {
        val token = uri.pathSegments.firstOrNull() ?: return null
        val s = live[token] ?: return null
        if (System.currentTimeMillis() > s.expires) {
            live.remove(token)?.key?.fill(0)
            return null
        }
        return s
    }

    fun isLive(uri: Uri) = get(uri) != null

    fun clear() {
        live.values.forEach { it.key.fill(0) }
        live.clear()
    }
}
