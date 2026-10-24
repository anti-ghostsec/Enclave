package app.enclave.crypto

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM helpers. Every key in Enclave is 256 bits, which keeps a 128-bit security
 * margin even against a quantum attacker running Grover's algorithm. Enclave uses no
 * public-key cryptography (RSA/ECC), which is the part quantum computers actually break.
 */
object Aead {
    const val KEY_BYTES = 32
    const val NONCE_BYTES = 12
    const val TAG_BYTES = 16

    private val rng = SecureRandom()

    fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    /** Returns nonce || ciphertext || tag. */
    fun seal(key: ByteArray, plain: ByteArray, aad: ByteArray? = null): ByteArray {
        val nonce = random(NONCE_BYTES)
        return nonce + raw(Cipher.ENCRYPT_MODE, key, nonce, plain, aad)
    }

    /** Throws [javax.crypto.AEADBadTagException] if the key is wrong or data was tampered with. */
    fun open(key: ByteArray, sealed: ByteArray, aad: ByteArray? = null): ByteArray {
        require(sealed.size >= NONCE_BYTES + TAG_BYTES) { "ciphertext too short" }
        val nonce = sealed.copyOfRange(0, NONCE_BYTES)
        return raw(Cipher.DECRYPT_MODE, key, nonce, sealed.copyOfRange(NONCE_BYTES, sealed.size), aad)
    }

    fun raw(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray, aad: ByteArray?): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
        aad?.let { c.updateAAD(it) }
        return c.doFinal(input)
    }

    /** Derives an independent 256-bit subkey from [key] for a given purpose. */
    fun subkey(key: ByteArray, label: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(label.toByteArray())
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        parts.forEach { md.update(it) }
        return md.digest()
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    fun wipe(b: ByteArray?) {
        b?.fill(0)
    }
}
