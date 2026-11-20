package app.enclave.vault

import android.content.Context
import android.net.Uri
import app.enclave.crypto.Aead
import app.enclave.crypto.BlobSource
import java.util.concurrent.ConcurrentHashMap

/**
 * Files you hand to another app (a video player, a forum's upload button, the share sheet).
 *
 * Each share holds only that one file's key, so it keeps working after Enclave auto-locks (the
 * player can keep playing, the browser can finish uploading) without keeping the vault itself
 * open. Shares end when the screen turns off, after [LIFETIME_MS], or with [clear]. Ones that read
 * from the open vault also end when it locks.
 *
 * A link is content://<package>.files/<random token>/file.<extension>: the file's name isn't in
 * it (the receiving app asks for that, see DecryptedFileProvider), only the extension, which the
 * file's type gives away anyway and some apps need to recognise it. The authority keeps the
 * package name: it has to be unique on the phone, and any app can look up which package owns an
 * authority, so another name wouldn't hide anything.
 */
object Shares {
    const val LIFETIME_MS = 30 * 60 * 1000L

    class Share(
        val open: () -> BlobSource, val key: ByteArray, val name: String, val mime: String, val size: Long, val expires: Long,
        /** True if it reads from the open vault, so it ends when the vault locks. */
        val needsVault: Boolean,
    )

    private val live = ConcurrentHashMap<String, Share>()

    private val main by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    /** Time since boot, sleep included: unlike the clock, it can't be set back to keep a link alive. */
    private fun now() = android.os.SystemClock.elapsedRealtime()

    fun create(context: Context, store: VaultStore, e: Entry): Uri {
        val token = Aead.hex(Aead.random(16))
        live[token] = Share(
            store.shareSource(e), store.keyBytes(e), e.name, e.mime, e.size, now() + LIFETIME_MS,
            needsVault = !store.sharesOutliveLock(e),
        )
        // Expired links are swept away (their keys zeroed) even if nothing asks for them again.
        main.postDelayed({ sweep() }, LIFETIME_MS + 1000)
        val ext = e.name.substringAfterLast('.', "").lowercase().takeIf { it.isNotEmpty() && it.length <= 8 && it.all(Char::isLetterOrDigit) }
        return Uri.parse("content://${context.packageName}.files/$token" + if (ext != null) "/file.$ext" else "")
    }

    /** Ends every link that has expired, zeroing its key. */
    fun sweep() {
        val now = now()
        live.entries.filter { now > it.value.expires }.forEach { (token, s) -> if (live.remove(token, s)) s.key.fill(0) }
    }

    /** Called when the vault locks: ends expired links, and those that read from the vault. */
    fun vaultLocked() {
        sweep()
        live.entries.filter { it.value.needsVault }.forEach { (token, s) -> if (live.remove(token, s)) s.key.fill(0) }
    }

    fun get(uri: Uri): Share? {
        val token = uri.pathSegments.firstOrNull() ?: return null
        val s = live[token] ?: return null
        if (now() > s.expires) {
            live.remove(token)?.key?.fill(0)
            return null
        }
        return s
    }

    fun isLive(uri: Uri) = get(uri) != null

    /** How much longer a live link needs the vault to stay open; 0 if none does. */
    fun vaultNeededForMs(): Long {
        val now = now()
        return live.values.filter { it.needsVault }.maxOfOrNull { it.expires - now }?.coerceIn(0, LIFETIME_MS) ?: 0
    }

    fun clear() {
        live.values.forEach { it.key.fill(0) }
        live.clear()
    }
}
