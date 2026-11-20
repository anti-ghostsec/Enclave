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
 *
 * Each save is sealed by a new key and the one before is deleted (see [StateKey]), so an older
 * copy of the file put back can't be opened. Neither that nor a missing file is taken as a fresh
 * start while a vault exists: see [distrust].
 */
object PlainPrefs {
    private lateinit var app: Context
    private lateinit var file: File
    /** The vault's header. While it's there, the state file must be too. */
    private lateinit var header: File
    private val values = HashMap<String, String>()
    private val json = Json

    fun init(c: Context) {
        app = c.applicationContext
        file = File(app.noBackupFilesDir, "state.bin")
        header = File(app.noBackupFilesDir, "header.bin")
        load()
        moveOldPreferences()
    }

    /**
     * True while the state file is there but the hardware key that opens it isn't answering.
     * Nothing is saved over the file then (it holds the count of wrong passwords and the wipe
     * setting), and reading it is tried again each time something is asked for.
     */
    @Volatile private var unreadable = false

    private fun decode(plain: ByteArray): Map<String, String> =
        json.decodeFromString<Map<String, String>>(String(plain)) - PAD

    /** The state file opened and read, or null if no state key opens it or it doesn't parse. */
    private fun readFile(): Map<String, String>? {
        val opened = StateKey.open(file.readBytes()) ?: return null
        return try {
            // A save cut off before it deleted the key before it leaves two: the other one goes now.
            runCatching { decode(opened.plain) }.getOrNull()?.also { runCatching { StateKey.retireAllBut(opened.alias) } }
        } finally {
            opened.plain.fill(0)
        }
    }

    @Synchronized
    private fun load() {
        unreadable = false
        val tmp = File(file.path + ".tmp")
        // A save cut off after the old file was deleted and before the new one took its place.
        if (!file.exists() && tmp.exists()) tmp.renameTo(file)
        if (!file.exists()) {
            if (!header.exists()) return
            // Versions before 0.4.0 kept these settings in plain preferences and had no state
            // key: that is moving up from one of them (see moveOldPreferences), not a deletion.
            val keys = try {
                StateKey.hasKeys()
            } catch (_: Exception) {
                unreadable = true
                return
            }
            if (keys || !hasOldPreferences()) distrust()
            return
        }
        val saved = try {
            readFile()
        } catch (_: Exception) {
            // The file or the keystore couldn't be read at all: try again later.
            unreadable = true
            return
        }
        if (saved != null) {
            values.clear()
            values += saved
            return
        }
        // Nothing opens it. If the keystore doesn't work at all (it can fail right after the
        // phone starts), keep the file and try again later.
        if (!StateKey.works()) {
            unreadable = true
            return
        }
        // The keystore works, so the file is damaged or is an older copy put back (whose key was
        // deleted at the next save). With no vault there's nothing to protect: start afresh.
        values.clear()
        if (header.exists()) distrust()
    }

    /** The wipe setting [distrust] puts in place; the count of wrong passwords starts one below it. */
    private const val DISTRUST_WIPE_AFTER = 20

    /**
     * A vault exists but the state that counts its wrong passwords is missing or can't be opened.
     * That only happens if the file was deleted, damaged or swapped for an older copy, which is
     * how someone able to write Enclave's files would undo the count to keep guessing. So assume
     * the worst: the longest lock-out starts now, and the next wrong password wipes the vault. A
     * copy of this state put back later doesn't open either, and starts this over.
     *
     * The other settings in it can't be known. The disguise is read back from the app's own
     * launcher entry; the calculator front and its code are lost and have to be set again. The
     * real vault says what happened when it's next opened (see [wasDistrusted]).
     */
    private fun distrust() {
        values.clear()
        values["failed"] = (DISTRUST_WIPE_AFTER - 1).toString()
        values["failed_at"] = System.currentTimeMillis().toString()
        values["failed_since_boot"] = SystemClock.elapsedRealtime().toString()
        values["failed_boot"] = bootCount().toString()
        values["wipe_after"] = DISTRUST_WIPE_AFTER.toString()
        values["distrusted"] = "true"
        // A vault that may be in the containers must not be made again in its place.
        if (File(app.noBackupFilesDir, "store").list()?.isNotEmpty() == true) values["main_in_containers"] = "true"
        launcherDisguise()?.let { values["disguise"] = it }
        persist()
    }

    /** Which disguise's launcher entry is on (its alias is "app.enclave.alias.<id>"). */
    private fun launcherDisguise(): String? = runCatching {
        val main = android.content.Intent(android.content.Intent.ACTION_MAIN)
            .addCategory(android.content.Intent.CATEGORY_LAUNCHER).setPackage(app.packageName)
        app.packageManager.queryIntentActivities(main, 0)
            .map { it.activityInfo.name }
            .firstOrNull { it.startsWith("app.enclave.alias.") }
            ?.removePrefix("app.enclave.alias.")
    }.getOrNull()

    /**
     * Set when the lock-out state had to be replaced by the strictest one (see [distrust]), until
     * the real vault has said so.
     */
    val wasDistrusted get() = get("distrusted") == "true"

    fun clearDistrusted() = set("distrusted", null)

    const val DISTRUSTED_MESSAGE =
        "Enclave's lock settings were missing or couldn't be opened, so the strictest were put in their place: " +
            "wipe after 20 wrong passwords, and the calculator front off. That happens if their file was deleted, " +
            "damaged or replaced with an older copy. Check them in Settings."

    private const val PAD = "_pad"
    private const val STATE_BLOCK = 2048

    /** The state as JSON, filled up to a whole number of [STATE_BLOCK] bytes. */
    internal fun paddedJson(state: Map<String, String>): String {
        val bare = json.encodeToString(state + (PAD to "")).toByteArray().size
        val target = (bare + STATE_BLOCK - 1) / STATE_BLOCK * STATE_BLOCK
        return json.encodeToString(state + (PAD to "x".repeat(target - bare)))
    }

    private fun hasOldPreferences() = app.getSharedPreferences("enclave", Context.MODE_PRIVATE).all.isNotEmpty()

    /** Earlier versions kept these in plain Android preferences: seal them, then delete those. */
    private fun moveOldPreferences() {
        val old = app.getSharedPreferences("enclave", Context.MODE_PRIVATE)
        val all = old.all
        if (all.isEmpty()) return
        all.forEach { (k, v) -> if (v != null && k !in values) values[k] = v.toString() }
        if (!persist()) return
        // Only once the sealed copy reads back correctly does the plain one go.
        val check = runCatching { synchronized(this) { readFile() } }.getOrNull()
        if (check == values) {
            old.edit().clear().commit()
            app.deleteSharedPreferences("enclave")
        }
    }

    /**
     * Saves the state under a new key. The key before is deleted only once the new file is in
     * place, so a crash at any point leaves a file that one of the keys still opens.
     */
    @Synchronized
    private fun persist(): Boolean {
        if (unreadable) return false
        val plain = paddedJson(values.toMap()).toByteArray()
        val (sealed, alias) = try {
            StateKey.sealFresh(plain)
        } catch (_: Exception) {
            return false
        } finally {
            plain.fill(0)
        }
        // Whether the file on the disk (or the one about to replace it) needs the new key.
        var needed = false
        return try {
            val tmp = File(file.path + ".tmp")
            FileOutputStream(tmp).use { it.write(sealed); it.fd.sync() }
            if (!tmp.renameTo(file)) {
                file.delete()
                needed = true
                if (!tmp.renameTo(file)) throw java.io.IOException("couldn't save the state")
            }
            needed = true
            file.setLastModified(VaultStore.FIXED_TIME)
            runCatching { StateKey.retireAllBut(alias) }
            true
        } catch (_: Exception) {
            if (!needed) runCatching { StateKey.discard(alias) }
            false
        }
    }

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

    /** Clears the count of wrong passwords, and with it the record of a wipe for them. */
    fun resetFailures() {
        synchronized(this) {
            if (unreadable) load()
            values["failed"] = "0"
            values.remove("wiped_ms")
        }
        persist()
    }

    /**
     * How long the wipe for too many wrong passwords took, once it has run; null before. Every
     * wrong password after it takes as long instead of wiping again (see VaultActions.unlock).
     */
    var wipedForFailuresMs: Long?
        get() = get("wiped_ms")?.toLongOrNull()
        set(v) = set("wiped_ms", v?.toString())

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
