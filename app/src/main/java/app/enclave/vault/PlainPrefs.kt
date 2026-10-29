package app.enclave.vault

import android.content.Context
import android.os.SystemClock
import android.provider.Settings
import app.enclave.crypto.Aead
import app.enclave.crypto.Kdf
import app.enclave.crypto.StateKey
import kotlinx.serialization.json.Json
import java.io.File
import java.io.FileOutputStream

/**
 * Settings that must be readable while the vault is locked (disguise, lock behaviour, lock-out
 * state). They're kept in one file sealed by a key in the phone's secure hardware ([StateKey]),
 * not in Android's plain preferences, so copying the app's files off the phone shows nothing:
 * not whether a disguise is on, nor anything about the calculator code.
 */
object PlainPrefs {
    private lateinit var app: Context
    private lateinit var file: File
    private val values = HashMap<String, String>()
    private val json = Json

    fun init(c: Context) {
        app = c.applicationContext
        file = File(app.noBackupFilesDir, "state.bin")
        if (file.exists()) {
            runCatching { values += json.decodeFromString<Map<String, String>>(String(StateKey.open(file.readBytes()))) }
        }
        moveOldPreferences()
    }

    /** Earlier versions kept these in plain Android preferences: seal them, then delete those. */
    private fun moveOldPreferences() {
        val old = app.getSharedPreferences("enclave", Context.MODE_PRIVATE)
        val all = old.all
        if (all.isEmpty()) return
        all.forEach { (k, v) -> if (v != null && k !in values) values[k] = v.toString() }
        if (!persist()) return
        // Only once the sealed copy reads back correctly does the plain one go.
        val check = runCatching { json.decodeFromString<Map<String, String>>(String(StateKey.open(file.readBytes()))) }.getOrNull()
        if (check == values) {
            old.edit().clear().commit()
            app.deleteSharedPreferences("enclave")
        }
    }

    @Synchronized
    private fun persist(): Boolean = runCatching {
        val sealed = StateKey.seal(json.encodeToString(values.toMap()).toByteArray())
        val tmp = File(file.path + ".tmp")
        FileOutputStream(tmp).use { it.write(sealed); it.fd.sync() }
        if (!tmp.renameTo(file)) {
            file.delete(); tmp.renameTo(file)
        }
        file.setLastModified(VaultStore.FIXED_TIME)
    }.isSuccess

    private fun get(k: String): String? = synchronized(this) { values[k] }

    private fun set(k: String, v: String?) {
        synchronized(this) { if (v == null) values.remove(k) else values[k] = v }
        persist()
    }

    var disguise: String
        get() = get("disguise") ?: "Default"
        set(v) = set("disguise", v)

    var calculatorFacade: Boolean
        get() = get("calc_facade").toBoolean()
        set(v) = set("calc_facade", v.toString())

    /** Light Argon2id: checked on every "=", but still far slower to guess than a plain hash. */
    private val CODE_KDF = Kdf.Params(memoryKiB = 16 * 1024, iterations = 2, parallelism = 1)

    private fun codeHash(code: String, salt: ByteArray) = Aead.hex(Kdf.derive(code.toCharArray(), null, salt, CODE_KDF))

    fun setCalculatorCode(code: String) {
        val salt = Aead.random(16)
        synchronized(this) {
            values["calc_salt"] = Aead.hex(salt)
            values["calc_kdf"] = codeHash(code, salt)
            values.remove("calc_hash")
        }
        persist()
    }

    fun checkCalculatorCode(code: String): Boolean {
        val salt = get("calc_salt")?.let { s -> s.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } ?: return false
        get("calc_kdf")?.let { return java.security.MessageDigest.isEqual(codeHash(code, salt).toByteArray(), it.toByteArray()) }
        // A code set by an earlier version (single SHA-256): accept it once, then upgrade it.
        val old = get("calc_hash") ?: return false
        val ok = java.security.MessageDigest.isEqual(Aead.hex(Aead.sha256(salt, code.toByteArray())).toByteArray(), old.toByteArray())
        if (ok) setCalculatorCode(code)
        return ok
    }

    val hasCalculatorCode get() = get("calc_kdf") != null || get("calc_hash") != null

    /** Seconds in the background before auto-lock. 0 = immediately. */
    var autoLockSeconds: Int
        get() = get("auto_lock")?.toIntOrNull() ?: 0
        set(v) = set("auto_lock", v.toString())

    /** Wipe everything after this many wrong passwords in a row. 0 = never. */
    var wipeAfterFailures: Int
        get() = get("wipe_after")?.toIntOrNull() ?: 0
        set(v) = set("wipe_after", v.toString())

    val failedAttempts: Int get() = get("failed")?.toIntOrNull() ?: 0

    fun resetFailures() = set("failed", "0")

    private fun bootCount(): Int = runCatching { Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT) }.getOrDefault(-1)

    /** Notes a wrong password, with times the lock-out can trust (see [lockoutRemainingMs]). */
    fun recordFailure() {
        synchronized(this) {
            values["failed"] = (failedAttempts + 1).toString()
            values["failed_at"] = System.currentTimeMillis().toString()
            values["failed_since_boot"] = SystemClock.elapsedRealtime().toString()
            values["failed_boot"] = bootCount().toString()
        }
        persist()
    }

    /**
     * Exponential back-off after 5 wrong attempts: 30 s, 1 min, 2 min ... up to 1 h. Measured with
     * the time since boot, which can't be changed in Settings, so moving the clock forward doesn't
     * skip it; after a restart the full wait starts again from boot.
     */
    fun lockoutRemainingMs(): Long {
        val n = failedAttempts
        if (n < 5) return 0
        val delay = minOf(30_000L shl minOf(n - 5, 7), 3_600_000L)
        val now = SystemClock.elapsedRealtime()
        val sameBoot = get("failed_boot")?.toIntOrNull() == bootCount()
        val sinceBoot = get("failed_since_boot")?.toLongOrNull()
        val monotonic = if (sameBoot && sinceBoot != null) sinceBoot + delay - now else delay - now
        val wall = (get("failed_at")?.toLongOrNull() ?: 0) + delay - System.currentTimeMillis()
        return maxOf(monotonic, wall).coerceIn(0, delay)
    }

    /** Removes any keyfile location an earlier version remembered. Enclave no longer stores it. */
    fun forgetOldKeyfileLocation(c: Context) {
        val old = get("keyfile_uri") ?: return
        runCatching {
            c.contentResolver.releasePersistableUriPermission(android.net.Uri.parse(old), android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        set("keyfile_uri", null)
    }
}
