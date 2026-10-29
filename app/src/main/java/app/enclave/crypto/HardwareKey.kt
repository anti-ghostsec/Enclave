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
 */
object StateKey : KeystoreKey("enclave_state_v1", preferStrongBox = false)
