package app.enclave.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * A non-exportable AES-256 key in the phone's secure hardware (StrongBox when wanted and
 * available, otherwise the TEE). Whatever it seals can only be opened on this phone.
 */
open class KeystoreKey(private val alias: String, private val preferStrongBox: Boolean) {
    private fun keyStore() = KeyStore.getInstance(STORE).apply { load(null) }

    private fun getOrCreate(): SecretKey {
        (keyStore().getKey(alias, null) as? SecretKey)?.let { return it }
        if (!preferStrongBox) return generate(strongBox = false)
        return try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        } catch (_: java.security.ProviderException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE).run {
            init(spec)
            generateKey()
        }
    }

    fun isStrongBox(): Boolean = try {
        val key = getOrCreate()
        val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, STORE)
        val info = factory.getKeySpec(key, android.security.keystore.KeyInfo::class.java) as android.security.keystore.KeyInfo
        if (android.os.Build.VERSION.SDK_INT >= 31) info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        else false
    } catch (_: Exception) {
        false
    }

    fun seal(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, getOrCreate())
        return c.iv + c.doFinal(plain)
    }

    fun open(sealed: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, getOrCreate(), GCMParameterSpec(128, sealed, 0, Aead.NONCE_BYTES))
        return c.doFinal(sealed, Aead.NONCE_BYTES, sealed.size - Aead.NONCE_BYTES)
    }

    fun destroy() {
        runCatching { keyStore().deleteEntry(alias) }
    }

    /** Whether the key exists. Throws if the keystore can't be asked. */
    fun exists(): Boolean = keyStore().containsAlias(alias)

    /** Makes the key if it doesn't exist yet. */
    fun ensure() {
        getOrCreate()
    }

    private companion object {
        const val STORE = "AndroidKeyStore"
    }
}

/**
 * Wraps the vault header, so a copy of the app's files taken off the phone can't even be
 * brute-forced offline. Deleting this key crypto-shreds the vault instantly.
 */
object HardwareKey : KeystoreKey("enclave_header_v1", preferStrongBox = true)

/**
 * Seals the settings Enclave needs while locked (disguise, lock-out state). Kept through a wipe,
 * so the app looks exactly the same afterwards. The TEE is enough here, and much faster.
 *
 * Every save is sealed by a brand-new key, and the key before it is deleted once the new file is
 * in place. A copy of the file taken earlier (holding a lower count of wrong passwords) and put
 * back can then no longer be opened: its key is gone. Normally one key exists; two only if a
 * save was cut off, and the next load keeps whichever opens the file and deletes the other.
 * Versions up to 0.5.3 used one fixed key, "enclave_state_v1", which is opened the same way and
 * deleted at the first save.
 */
object StateKey {
    private const val PREFIX = "enclave_state_"
    private const val PROBE = "enclave_probe"

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** The state keys there are now. */
    private fun aliases(): List<String> = keyStore().aliases().toList().filter { it.startsWith(PREFIX) }

    /** What [open] found: the contents, and the key that opened them. */
    class Opened(val plain: ByteArray, val alias: String)

    /**
     * Opens [sealed] with whichever state key it was sealed by. Returns null only when there's
     * positive evidence that no key here sealed it: every state key there is rejected it as not
     * its own (the authentication tag didn't match), or there is no state key at all, or it's
     * too short to be sealed by any. Any other failure (the keystore busy or not answering, a
     * StrongBox or TEE hiccup) is thrown, so the caller can try again later instead of taking
     * a passing fault for tampering.
     */
    fun open(sealed: ByteArray): Opened? {
        if (sealed.size < Aead.NONCE_BYTES + Aead.TAG_BYTES) return null
        var failure: Exception? = null
        for (alias in aliases()) {
            try {
                return Opened(KeystoreKey(alias, preferStrongBox = false).open(sealed), alias)
            } catch (e: Exception) {
                if (!isRejection(e)) failure = e
            }
        }
        failure?.let { throw it }
        return null
    }

    /** Whether [e] says the key isn't the one that sealed the data, and nothing else. */
    fun isRejection(e: Throwable): Boolean =
        generateSequence(e) { it.cause }.take(8).any { it is javax.crypto.AEADBadTagException }

    /** Seals [plain] with a new key. Returns the sealed bytes and that key's alias. */
    fun sealFresh(plain: ByteArray): Pair<ByteArray, String> {
        val alias = PREFIX + Aead.hex(Aead.random(12))
        val key = KeystoreKey(alias, preferStrongBox = false)
        return try {
            key.seal(plain) to alias
        } catch (t: Throwable) {
            key.destroy()
            throw t
        }
    }

    /** Deletes every state key but [keep]: call only once the file sealed by [keep] is in place. */
    fun retireAllBut(keep: String) {
        aliases().filter { it != keep }.forEach { KeystoreKey(it, preferStrongBox = false).destroy() }
    }

    /** Whether any state key exists, which means a state file was saved at some point. */
    fun hasKeys(): Boolean = aliases().isNotEmpty()

    /** Deletes a key [sealFresh] made whose file never got into place. */
    fun discard(alias: String) = KeystoreKey(alias, preferStrongBox = false).destroy()

    /**
     * Set while the state file looks tampered with but that hasn't been confirmed on a later
     * start yet (see PlainPrefs). A key, not a file, so it isn't in the app's files.
     */
    val suspect = KeystoreKey("enclave_mark_suspect", preferStrongBox = false)

    /**
     * Set when the lock-out state was replaced by the strictest one, until the real password is
     * next typed. Someone who can write Enclave's files but not its keys can't clear it, so a
     * second replacement leaves no margin at all (see PlainPrefs.distrust).
     */
    val distrusted = KeystoreKey("enclave_mark_distrusted", preferStrongBox = false)

    /**
     * Seals a second, small record of the calculator front and its code (see PlainPrefs). Putting
     * an older copy of it back only brings back an older code, so it needs no fresh key per save.
     */
    val front = KeystoreKey("enclave_front_v1", preferStrongBox = false)
}

/**
 * Says a wipe is under way, from before the first thing is destroyed until the last is. Keys,
 * not files, so the mark isn't in the app's files and outlives the header it's about. If one is
 * found at a start, that wipe was cut off and is finished then (see VaultManager.recover).
 */
object WipeMark {
    enum class Kind {
        /** The lock screen stays as it was (a duress password, or too many wrong ones). */
        HIDDEN,
        /** Asked for in Settings: no vault is left, and Enclave offers to create one. */
        OPEN,
    }

    private val hidden = KeystoreKey("enclave_mark_wipe_hidden", preferStrongBox = false)
    private val open = KeystoreKey("enclave_mark_wipe_open", preferStrongBox = false)

    fun set(kind: Kind) = (if (kind == Kind.HIDDEN) hidden else open).ensure()

    /** The wipe that was cut off, if one was. Throws if the keystore can't be asked. */
    fun pending(): Kind? = when {
        hidden.exists() -> Kind.HIDDEN
        open.exists() -> Kind.OPEN
        else -> null
    }

    fun clear() {
        hidden.destroy()
        open.destroy()
    }
}
