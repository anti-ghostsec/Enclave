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
 * not whether a disguise is on, nor anything about the calculator code. What's sealed is filled
 * up to a fixed size, so the file's length doesn't show which settings are in it either.
 */
object PlainPrefs {
    private lateinit var app: Context
    private lateinit var file: File
    private val values = HashMap<String, String>()
    private val json = Json

    fun init(c: Context) {
        app = c.applicationContext
        file = File(app.noBackupFilesDir, "state.bin")
        load()
        moveOldPreferences()
    }

    /**
     * True while the state file is there but the hardware key that opens it isn't answering.
     * Nothing is saved over the file then (it holds the count of wrong passwords and the wipe
     * setting), and reading it is tried again each time something is asked for.
     */
    @Volatile private var unreadable = false

    private fun decode(sealed: ByteArray): Map<String, String> =
        json.decodeFromString<Map<String, String>>(String(StateKey.open(sealed))) - PAD

    @Synchronized
    private fun load() {
        unreadable = false
        if (!file.exists()) return
        val saved = runCatching { decode(file.readBytes()) }.getOrNull()
        if (saved != null) {
            values.clear()
            values += saved
            return
        }
        // It can't be read. If the key works on something else, the file itself is damaged and
        // there's nothing to wait for: start afresh, as before. If the key doesn't work (it can
        // fail right after the phone starts), keep the file and try again later.
        val probe = byteArrayOf(1, 2, 3)
        unreadable = !runCatching { StateKey.open(StateKey.seal(probe)).contentEquals(probe) }.getOrDefault(false)
    }

    private const val PAD = "_pad"
    private const val STATE_BLOCK = 2048

    /** The state as JSON, filled up to a whole number of [STATE_BLOCK] bytes. */
    internal fun paddedJson(state: Map<String, String>): String {
        val bare = json.encodeToString(state + (PAD to "")).toByteArray().size
        val target = (bare + STATE_BLOCK - 1) / STATE_BLOCK * STATE_BLOCK
        return json.encodeToString(state + (PAD to "x".repeat(target - bare)))
    }

    /** Earlier versions kept these in plain Android preferences: seal them, then delete those. */
    private fun moveOldPreferences() {
        val old = app.getSharedPreferences("enclave", Context.MODE_PRIVATE)
        val all = old.all
        if (all.isEmpty()) return
        all.forEach { (k, v) -> if (v != null && k !in values) values[k] = v.toString() }
        if (!persist()) return
        // Only once the sealed copy reads back correctly does the plain one go.
        val check = runCatching { decode(file.readBytes()) }.getOrNull()
        if (check == values) {
            old.edit().clear().commit()
            app.deleteSharedPreferences("enclave")
        }
    }

    @Synchronized
    private fun persist(): Boolean = !unreadable && runCatching {
        val sealed = StateKey.seal(paddedJson(values.toMap()).toByteArray())
        val tmp = File(file.path + ".tmp")
        FileOutputStream(tmp).use { it.write(sealed); it.fd.sync() }
        if (!tmp.renameTo(file)) {
            file.delete(); tmp.renameTo(file)
        }
        file.setLastModified(VaultStore.FIXED_TIME)
    }.isSuccess

    private fun get(k: String): String? = synchronized(this) {
        if (unreadable) load()
        values[k]
    }

    private fun set(k: String, v: String?) {
        synchronized(this) {
            if (unreadable) load()
            if (v == null) values.remove(k) else values[k] = v
        }
        persist()
    }

    /**
     * Set once the real vault has been opened from the containers. If it's then not found there
     * one day, that's damage, not a new vault, and nothing must be made in its place.
     */
    var mainInContainers: Boolean
        get() = get("main_in_containers").toBoolean()
        set(v) { if (v != mainInContainers) set("main_in_containers", if (v) "true" else null) }

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

    /** What [beginAttempt] changed, so [cancelAttempt] can put it back. */
    class Attempt internal constructor(internal val before: Map<String, String?>, internal val counted: String)

    private val attemptKeys = listOf("failed", "failed_at", "failed_since_boot", "failed_boot")

    /**
     * Counts a password attempt as a wrong one before the password is tried, with times the
     * lock-out can trust (see [lockoutRemainingMs]), and only says yes once the count is on the
     * disk. Returns null if it couldn't be saved (storage full, say): the attempt must then not
     * be made, or a count kept only in memory could be thrown away by stopping the app, for
     * as many guesses as anyone likes. The real password clears the count with [resetFailures].
     */
    fun beginAttempt(): Attempt? = synchronized(this) {
        if (unreadable) load()
        val before = attemptKeys.associateWith { values[it] }
        val counted = (failedAttempts + 1).toString()
        values["failed"] = counted
        values["failed_at"] = System.currentTimeMillis().toString()
        values["failed_since_boot"] = SystemClock.elapsedRealtime().toString()
        values["failed_boot"] = bootCount().toString()
        if (persist()) Attempt(before, counted) else {
            before.forEach { (k, v) -> if (v == null) values.remove(k) else values[k] = v }
            null
        }
    }

    /**
     * Takes one attempt back out of the count, leaving the count as it was before it: for a
     * password that opened something other than the real vault. Wrong passwords counted before
     * it stay counted.
     */
    fun cancelAttempt(a: Attempt) {
        synchronized(this) {
            if (values["failed"] == a.counted) {
                a.before.forEach { (k, v) -> if (v == null) values.remove(k) else values[k] = v }
            } else {
                // Another attempt was counted meanwhile: take off just this one.
                values["failed"] = (failedAttempts - 1).coerceAtLeast(0).toString()
            }
        }
        persist()
    }

    /** How long to refuse attempts when the count of them can't be saved. */
    const val UNSAVED_WAIT_MS = 30_000L

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
