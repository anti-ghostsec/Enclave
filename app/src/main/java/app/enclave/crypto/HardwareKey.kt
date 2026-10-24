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
 * A non-exportable AES-256 key that lives in the phone's secure hardware (StrongBox when
 * available, otherwise the TEE). The vault header is wrapped with it, so a copy of the
 * app's files taken off the phone can't even be brute-forced offline. Deleting this key
 * crypto-shreds the vault instantly.
 */
object HardwareKey {
    private const val ALIAS = "enclave_header_v1"
    private const val STORE = "AndroidKeyStore"

    private fun keyStore() = KeyStore.getInstance(STORE).apply { load(null) }

    private fun getOrCreate(): SecretKey {
        (keyStore().getKey(ALIAS, null) as? SecretKey)?.let { return it }
        return try {
            generate(strongBox = true)
        } catch (_: StrongBoxUnavailableException) {
            generate(strongBox = false)
        } catch (_: java.security.ProviderException) {
            generate(strongBox = false)
        }
    }

    private fun generate(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
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
        runCatching { keyStore().deleteEntry(ALIAS) }
    }
}
