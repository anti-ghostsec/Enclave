package app.enclave.vault

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import app.enclave.crypto.Aead

/**
 * Settings that must be readable while the vault is locked (disguise, lock behaviour).
 * Nothing secret is stored here.
 */
object PlainPrefs {
    private lateinit var p: SharedPreferences

    fun init(c: Context) {
        p = c.getSharedPreferences("enclave", Context.MODE_PRIVATE)
    }

    var disguise: String
        get() = p.getString("disguise", "Default")!!
        set(v) = p.edit { putString("disguise", v) }

    var calculatorFacade: Boolean
        get() = p.getBoolean("calc_facade", false)
        set(v) = p.edit { putBoolean("calc_facade", v) }

    fun setCalculatorCode(code: String) {
        val salt = Aead.random(16)
        p.edit {
            putString("calc_salt", Aead.hex(salt))
            putString("calc_hash", Aead.hex(Aead.sha256(salt, code.toByteArray())))
        }
    }

    fun checkCalculatorCode(code: String): Boolean {
        val salt = p.getString("calc_salt", null) ?: return false
        val hash = p.getString("calc_hash", null) ?: return false
        val saltBytes = salt.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        return java.security.MessageDigest.isEqual(
            Aead.hex(Aead.sha256(saltBytes, code.toByteArray())).toByteArray(), hash.toByteArray()
        )
    }

    val hasCalculatorCode get() = p.contains("calc_hash")

    /** Seconds in the background before auto-lock. 0 = immediately. */
    var autoLockSeconds: Int
        get() = p.getInt("auto_lock", 0)
        set(v) = p.edit { putInt("auto_lock", v) }

    /** Wipe everything after this many wrong passwords in a row. 0 = never. */
    var wipeAfterFailures: Int
        get() = p.getInt("wipe_after", 0)
        set(v) = p.edit { putInt("wipe_after", v) }

    var failedAttempts: Int
        get() = p.getInt("failed", 0)
        set(v) = p.edit { putInt("failed", v) }

    var lastFailureAt: Long
        get() = p.getLong("failed_at", 0)
        set(v) = p.edit { putLong("failed_at", v) }

    /** Removes any keyfile location an earlier version remembered. Enclave no longer stores it. */
    fun forgetOldKeyfileLocation(c: Context) {
        val old = p.getString("keyfile_uri", null) ?: return
        runCatching {
            c.contentResolver.releasePersistableUriPermission(android.net.Uri.parse(old), android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        p.edit { remove("keyfile_uri") }
    }

    /** Exponential back-off after 5 wrong attempts: 30 s, 1 min, 2 min ... up to 1 h. */
    fun lockoutRemainingMs(now: Long = System.currentTimeMillis()): Long {
        val n = failedAttempts
        if (n < 5) return 0
        val delay = minOf(30_000L shl minOf(n - 5, 7), 3_600_000L)
        return (lastFailureAt + delay - now).coerceAtLeast(0)
    }
}
