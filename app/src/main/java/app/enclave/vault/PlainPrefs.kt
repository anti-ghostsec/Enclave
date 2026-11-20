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
 * start while a vault exists: see [StateTrust] and [distrust].
 */
object PlainPrefs {
    private lateinit var app: Context
    private lateinit var file: File
    /** The vault's header. While it's there, the state file must be too. */
    private lateinit var header: File
    /** A second record of the calculator front alone, which [distrust] keeps (see [saveFront]). */
    private lateinit var frontFile: File
    private val values = HashMap<String, String>()
    private val json = Json

    fun init(c: Context) {
        app = c.applicationContext
        file = File(app.noBackupFilesDir, "state.bin")
        header = File(app.noBackupFilesDir, "header.bin")
        frontFile = File(app.noBackupFilesDir, "front.bin")
        load()
        synchronized(this) {
            if (!unreadable && file.exists()) {
                // Sealed afresh at every start, so the newest state key and the file's change time
                // say when Enclave last started, which a password typed or not.
                persist()
                if (!frontFile.exists()) saveFront()
            }
        }
        moveOldPreferences()
    }

    /**
     * True while the state file can't be used yet: the keystore isn't answering, or the file
     * looks tampered with and that hasn't been confirmed (see [StateTrust]). Nothing is saved
     * over the file then (it holds the count of wrong passwords and the wipe setting), so no
     * password can be tried, and reading it is tried again each time something is asked for.
     */
    @Volatile private var unreadable = false

    /** Whether the plain preferences are ones to move over (see [moveOldPreferences]). */
    @Volatile private var moveOld = false

    /** When this run of the app first suspected the state file; -1 if it hasn't. */
    private var suspectedAt = -1L
    /** Whether an earlier run of the app had suspected it already; null until asked. */
    private var suspectedBefore: Boolean? = null

    private fun decode(plain: ByteArray): Map<String, String> =
        json.decodeFromString<Map<String, String>>(String(plain)) - PAD

    /**
     * The state file opened and read; null if every state key rejected it (see [StateKey.open])
     * or what it holds doesn't parse. Throws for anything that may pass.
     */
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
        moveOld = false
        val tmp = File(file.path + ".tmp")
        // A save cut off after the old file was deleted and before the new one took its place.
        if (!file.exists() && tmp.exists()) tmp.renameTo(file)
        var saved: Map<String, String>? = null
        val found = if (!file.exists()) StateTrust.Found.MISSING else try {
            saved = readFile()
            if (saved != null) StateTrust.Found.OPENED else StateTrust.Found.REJECTED
        } catch (_: Exception) {
            StateTrust.Found.ERROR
        }
        val vault = header.exists()
        val keys = if (found == StateTrust.Found.MISSING && vault) runCatching { StateKey.hasKeys() }.getOrNull() else null
        val old = found == StateTrust.Found.MISSING && vault && keys == false && hasOldPreferences()
        val suspicious = vault && !old &&
            (found == StateTrust.Found.REJECTED || (found == StateTrust.Found.MISSING && keys != null))
        if (suspicious && suspectedAt < 0) {
            // Asked before the mark is set, so it says whether an earlier run set it.
            if (suspectedBefore == null) suspectedBefore = runCatching { StateKey.suspect.exists() }.getOrDefault(false)
            suspectedAt = SystemClock.elapsedRealtime()
            runCatching { StateKey.suspect.ensure() }
        }
        val action = StateTrust.decide(
            found, vault, keys, old,
            suspectedBefore = suspectedBefore == true,
            suspectedForMs = if (suspectedAt < 0) -1 else SystemClock.elapsedRealtime() - suspectedAt,
        )
        when (action) {
            StateTrust.Action.USE -> {
                values.clear()
                values += saved!!
                clearSuspicion()
            }
            StateTrust.Action.START_EMPTY -> {
                values.clear()
                clearSuspicion()
                // With no vault there's nothing to protect, so old settings may come over too.
                moveOld = found == StateTrust.Found.MISSING && hasOldPreferences()
            }
            StateTrust.Action.MOVE_OLD -> moveOld = true
            StateTrust.Action.RETRY, StateTrust.Action.SUSPECT -> unreadable = true
            StateTrust.Action.DISTRUST -> {
                distrust()
                clearSuspicion()
            }
        }
    }

    private fun clearSuspicion() {
        StateKey.suspect.destroy()
        suspectedAt = -1
        suspectedBefore = null
    }

    /** The wipe setting [distrust] puts in place. */
    private const val DISTRUST_WIPE_AFTER = 20

    /**
     * A vault exists but the state that counts its wrong passwords is missing or no state key
     * opens it, and that was seen again after a while (see [StateTrust]). That only happens if
     * the file was deleted, damaged or swapped for an older copy, which is how someone able to
     * write Enclave's files would undo the count to keep guessing. So assume the worst: the
     * longest lock-out starts now, and the third wrong password wipes the vault; if this has
     * happened before without the real password typed since, the next one does. A copy of this
     * state put back later doesn't open either, and starts this over.
     *
     * The other settings in it can't be known. The disguise is read back from the app's own
     * launcher entry, and the calculator front and its code from their own record ([saveFront]);
     * the rest go back to their defaults. The real vault says what happened when it's next
     * opened (see [wasDistrusted]).
     */
    private fun distrust() {
        // If the mark can't be read or set, take it as set: the stricter count.
        val before = runCatching { StateKey.distrusted.exists() }.getOrDefault(true)
        runCatching { StateKey.distrusted.ensure() }
        val front = runCatching { readFront() }.getOrNull()
        values.clear()
        values["failed"] = StateTrust.distrustCount(DISTRUST_WIPE_AFTER, before).toString()
        values["failed_at"] = System.currentTimeMillis().toString()
        values["failed_since_boot"] = SystemClock.elapsedRealtime().toString()
        values["failed_boot"] = bootCount().toString()
        values["wipe_after"] = DISTRUST_WIPE_AFTER.toString()
        values["distrusted"] = "true"
        // A vault that may be in the containers must not be made again in its place.
        if (File(app.noBackupFilesDir, "store").list()?.isNotEmpty() == true) values["main_in_containers"] = "true"
        launcherDisguise()?.let { values["disguise"] = it }
        front?.forEach { (k, v) -> if (k in FRONT_KEYS) values[k] = v }
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

    fun clearDistrusted() {
        set("distrusted", null)
    }

    const val DISTRUSTED_MESSAGE =
        "Enclave's lock settings were missing or couldn't be opened, so the strictest were put in their place: " +
            "wipe after 20 wrong passwords, a long wait before the next try, and auto-lock at once. The calculator " +
            "front and its code were kept if they could be read back. That happens if their file was deleted, " +
            "damaged or replaced with an older copy. Check them in Settings."

    // ---- The calculator front's own record ------------------------------------------------

    /** What the calculator front's record holds. */
    private val FRONT_KEYS = setOf("calc_facade", "calc_salt", "calc_kdf", "calc_hash")

    /** The record as last read, for while the state file can't be. */
    @Volatile private var frontCache: Map<String, String>? = null

    /**
     * Saves the calculator front and its code on their own, sealed by a fixed key. [distrust]
     * can't know them from the state file, and without them a calculator icon would open on a
     * password screen, which gives the front away. An older copy put back brings back an older
     * code and nothing else, so this record needs none of the state file's protection against
     * that. It's filled to the same size whatever it holds.
     */
    @Synchronized
    private fun saveFront() {
        if (unreadable) return
        val record = values.filterKeys { it in FRONT_KEYS }
        val plain = paddedJson(record).toByteArray()
        runCatching {
            val sealed = try {
                StateKey.front.seal(plain)
            } finally {
                plain.fill(0)
            }
            val tmp = File(frontFile.path + ".tmp")
            FileOutputStream(tmp).use { it.write(sealed); it.fd.sync() }
            if (!tmp.renameTo(frontFile)) {
                frontFile.delete()
                tmp.renameTo(frontFile)
            }
            frontFile.setLastModified(VaultStore.FIXED_TIME)
            frontCache = record
        }
    }

    /** The calculator front's record; null if there's none. Throws if it can't be read. */
    private fun readFront(): Map<String, String>? {
        if (!frontFile.exists()) return null
        val plain = StateKey.front.open(frontFile.readBytes())
        return try {
            decode(plain).filterKeys { it in FRONT_KEYS }.also { frontCache = it }
        } finally {
            plain.fill(0)
        }
    }

    /**
     * A setting of the calculator front. While the state file can't be used, its own record
     * stands in, so a calculator icon still opens on the calculator.
     */
    private fun front(k: String): String? = synchronized(this) {
        if (unreadable) load()
        if (!unreadable) return values[k]
        (frontCache ?: runCatching { readFront() }.getOrNull())?.get(k)
    }

    private const val PAD = "_pad"
    private const val STATE_BLOCK = 2048

    /** The state as JSON, filled up to a whole number of [STATE_BLOCK] bytes. */
    internal fun paddedJson(state: Map<String, String>): String {
        val bare = json.encodeToString(state + (PAD to "")).toByteArray().size
        val target = (bare + STATE_BLOCK - 1) / STATE_BLOCK * STATE_BLOCK
        return json.encodeToString(state + (PAD to "x".repeat(target - bare)))
    }

    private fun oldPreferences() = app.getSharedPreferences("enclave", Context.MODE_PRIVATE)

    /** Whether plain preferences are there that a version before 0.4.0 could have written. */
    private fun hasOldPreferences() = StateTrust.looksOld(oldPreferences().all.keys)

    /**
     * Versions before 0.4.0 kept these settings in plain Android preferences: seal them, then
     * delete those. Only when [load] found that's what this is (no state file, no state key, and
     * nothing in the preferences a later version would have written). Preferences found at any
     * other time weren't written by Enclave, and are deleted unread: otherwise a file planted
     * there could add settings the sealed state doesn't have, a record of a wipe that never ran
     * among them.
     */
    private fun moveOldPreferences() {
        val old = oldPreferences()
        val all = old.all
        if (all.isEmpty()) return
        if (!moveOld) {
            if (!unreadable) deleteOldPreferences()
            return
        }
        synchronized(this) {
            all.forEach { (k, v) -> if (v != null && k in StateTrust.OLD_PREFERENCE_KEYS && k !in values) values[k] = v.toString() }
        }
        if (!persist()) return
        moveOld = false
        saveFront()
        // Only once the sealed copy reads back correctly does the plain one go.
        val check = runCatching { synchronized(this) { readFile() } }.getOrNull()
        if (check == synchronized(this) { values.toMap() }) deleteOldPreferences()
    }

    private fun deleteOldPreferences() {
        oldPreferences().edit().clear().commit()
        app.deleteSharedPreferences("enclave")
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

    private fun set(k: String, v: String?): Boolean {
        synchronized(this) {
            if (unreadable) load()
            if (v == null) values.remove(k) else values[k] = v
        }
        return persist().also { if (it && k in FRONT_KEYS) saveFront() }
    }

    /**
     * Set once the real vault has been opened from the containers. If it's then not found there
     * one day, that's damage, not a new vault, and nothing must be made in its place.
     */
    var mainInContainers: Boolean
        get() = get("main_in_containers").toBoolean()
        set(v) { if (v != mainInContainers) set("main_in_containers", if (v) "true" else null) }

    /** While the state file can't be used, the launcher entry that is on says which it is. */
    var disguise: String
        get() = get("disguise") ?: (if (unreadable) launcherDisguise() else null) ?: "Default"
        set(v) { set("disguise", v) }

    var calculatorFacade: Boolean
        get() = front("calc_facade").toBoolean()
        set(v) { set("calc_facade", v.toString()) }

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
        if (persist()) saveFront()
    }

    fun checkCalculatorCode(code: String): Boolean {
        val salt = front("calc_salt")?.let { s -> s.chunked(2).map { it.toInt(16).toByte() }.toByteArray() } ?: return false
        front("calc_kdf")?.let { return java.security.MessageDigest.isEqual(codeHash(code, salt).toByteArray(), it.toByteArray()) }
        // A code set by an earlier version (single SHA-256): accept it once, then upgrade it.
        val old = front("calc_hash") ?: return false
        val ok = java.security.MessageDigest.isEqual(Aead.hex(Aead.sha256(salt, code.toByteArray())).toByteArray(), old.toByteArray())
        if (ok) setCalculatorCode(code)
        return ok
    }

    val hasCalculatorCode get() = front("calc_kdf") != null || front("calc_hash") != null

    /** Seconds in the background before auto-lock. 0 = immediately. */
    var autoLockSeconds: Int
        get() = get("auto_lock")?.toIntOrNull() ?: 0
        set(v) { set("auto_lock", v.toString()) }

    /** Wipe everything after this many wrong passwords in a row. 0 = never. */
    var wipeAfterFailures: Int
        get() = get("wipe_after")?.toIntOrNull() ?: 0
        set(v) { set("wipe_after", v.toString()) }

    val failedAttempts: Int get() = get("failed")?.toIntOrNull() ?: 0

    /**
     * Clears the count of wrong passwords, and with it the record of a wipe for them and the mark
     * that the state was replaced (see [distrust]). Returns false if that couldn't be saved.
     */
    fun resetFailures(): Boolean {
        synchronized(this) {
            if (unreadable) load()
            values["failed"] = "0"
            values.remove("wiped_ms")
        }
        return persist().also { if (it) StateKey.distrusted.destroy() }
    }

    /**
     * How long the wipe for too many wrong passwords took, once it has run; null before. Every
     * wrong password after it takes as long instead of wiping again (see VaultActions.unlock).
     */
    var wipedForFailuresMs: Long?
        get() = get("wiped_ms")?.toLongOrNull()
        set(v) { set("wiped_ms", v?.toString()) }

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
