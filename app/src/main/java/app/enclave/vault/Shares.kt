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
 * from the open vault also end when it locks, and all of one vault's end as soon as a different
 * vault is unlocked (a decoy above all): a link from the real vault must not still work then. When
 * a share ends, its key is zeroed and every reader open on it is closed, zeroing their copies.
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
        /** Which vault it's from (see [VaultStore.shareOwner]). */
        val owner: ByteArray,
    ) {
        /** Readers open on it (see DecryptedFileProvider), each with its own copy of the key. */
        internal val readers: MutableSet<java.io.Closeable> = ConcurrentHashMap.newKeySet()

        internal fun end() {
            key.fill(0)
            owner.fill(0)
            readers.toList().forEach { r -> if (readers.remove(r)) runCatching { r.close() } }
        }
    }

    private val live = ConcurrentHashMap<String, Share>()

    private val main by lazy { android.os.Handler(android.os.Looper.getMainLooper()) }

    /** Time since boot, sleep included: unlike the clock, it can't be set back to keep a link alive. */
    private fun now() = android.os.SystemClock.elapsedRealtime()

    fun create(context: Context, store: VaultStore, e: Entry): Uri {
        val token = Aead.hex(Aead.random(16))
        live[token] = Share(
            store.shareSource(e), store.keyBytes(e), e.name, e.mime, e.size, now() + LIFETIME_MS,
            needsVault = !store.sharesOutliveLock(e), owner = store.shareOwner.copyOf(),
        )
        // Expired links are swept away (their keys zeroed) even if nothing asks for them again.
        main.postDelayed({ sweep() }, LIFETIME_MS + 1000)
        val ext = e.name.substringAfterLast('.', "").lowercase().takeIf { it.isNotEmpty() && it.length <= 8 && it.all(Char::isLetterOrDigit) }
        return Uri.parse("content://${context.packageName}.files/$token" + if (ext != null) "/file.$ext" else "")
    }

    /** Ends the links that match [which]. */
    private fun endWhere(which: (Share) -> Boolean) {
        live.entries.filter { which(it.value) }.forEach { (token, s) -> if (live.remove(token, s)) s.end() }
    }

    /** Ends every link that has expired, zeroing its key and closing its readers. */
    fun sweep() {
        val now = now()
        endWhere { now > it.expires }
    }

    /** Called when the vault locks: ends expired links, and those that read from the vault. */
    fun vaultLocked() {
        sweep()
        endWhere { it.needsVault }
    }

    /** Called when a vault is unlocked: ends every link from any other vault. */
    fun vaultOpened(owner: ByteArray) {
        endWhere { !it.owner.contentEquals(owner) }
    }

    fun get(uri: Uri): Share? {
        val token = uri.pathSegments.firstOrNull() ?: return null
        val s = live[token] ?: return null
        if (now() > s.expires) {
            if (live.remove(token, s)) s.end()
            return null
        }
        return s
    }

    /**
     * Ties [reader] to the share [uri] names, so it's closed when the share ends. Returns false,
     * having closed it, if the share has ended already.
     */
    fun attach(uri: Uri, share: Share, reader: java.io.Closeable): Boolean {
        share.readers += reader
        // Checked after adding: a share that ends from here on closes it itself.
        if (get(uri) === share) return true
        detach(share, reader)
        return false
    }

    /** Closes [reader], unless the share's end has closed it already. */
    fun detach(share: Share, reader: java.io.Closeable) {
        if (share.readers.remove(reader)) runCatching { reader.close() }
    }

    fun isLive(uri: Uri) = get(uri) != null

    /** How much longer a live link needs the vault to stay open; 0 if none does. */
    fun vaultNeededForMs(): Long {
        val now = now()
        return live.values.filter { it.needsVault }.maxOfOrNull { it.expires - now }?.coerceIn(0, LIFETIME_MS) ?: 0
    }

    fun clear() {
        endWhere { true }
    }
}
