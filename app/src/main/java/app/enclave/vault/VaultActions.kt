package app.enclave.vault

import android.os.SystemClock
import app.enclave.crypto.Aead

/** Higher-level vault operations used by the UI. All of these are slow (Argon2) — call off the main thread. */
object VaultActions {
    sealed interface Outcome {
        data object Opened : Outcome
        data object Wrong : Outcome
        data class LockedOut(val ms: Long) : Outcome
        /** The count of attempts couldn't be saved (storage full, say), so nothing was tried. */
        data object NotSaved : Outcome
    }

    /**
     * One attempt at a time, whichever screen it comes from: two started together would both
     * pass the lock-out check before either was counted.
     */
    @Synchronized
    fun unlock(password: CharArray, keyfileSecret: ByteArray?): Outcome {
        PlainPrefs.lockoutRemainingMs().let { if (it > 0) return Outcome.LockedOut(it) }
        // The attempt is counted, on the disk, before the password is tried. If the count can't
        // be saved, nothing is tried.
        val attempt = PlainPrefs.beginAttempt() ?: return Outcome.NotSaved
        // A wipe that was cut off, and that the start couldn't finish, is finished first.
        VaultManager.recover()
        // Duress passwords never use a keyfile, so with a keyfile selected the password is also
        // tried without it. Both are always tried, so a duress password takes exactly as long as
        // the real one and the time taken gives nothing away.
        val withKeyfile = VaultManager.unlock(password, keyfileSecret)
        // A tag of the password typed, as it is without the keyfile: kept by the session it
        // opens, so the same password can't be added there as a duress password (see [taken]).
        var alone: ByteArray? = null
        val without = if (keyfileSecret != null) VaultManager.unlock(password, null) { alone = it } else null
        val r = withKeyfile ?: without
        // The same password opens this vault with the keyfile and a duress slot without it.
        // Versions up to 0.6.0 let that be set up; the real vault says so once it's open.
        val sameAsDuress = withKeyfile?.role == Role.MAIN && without != null
        if (withKeyfile != null) without?.master?.let(Aead::wipe) else alone?.fill(0).also { alone = null }
        if (r == null) {
            val max = PlainPrefs.wipeAfterFailures
            if (max > 0 && PlainPrefs.failedAttempts >= max) {
                val wiped = PlainPrefs.wipedForFailuresMs
                if (wiped == null) {
                    // Destroy everything, but look exactly as before: the lock screen stays, and
                    // from now on every password is simply "wrong". The count of wrong passwords
                    // stays too, so the lock-out goes on growing as it would have.
                    val start = SystemClock.elapsedRealtime()
                    wipeEverything(keepCount = true, keepLockScreen = true)
                    PlainPrefs.wipedForFailuresMs = SystemClock.elapsedRealtime() - start
                } else {
                    // Already done once. Wiping again would write a new header (and make a new
                    // hardware key) at every wrong password, which its file times would show.
                    // Nothing is left to destroy: take as long as the wipe did, and leave the
                    // header alone. The state is saved again, as the wipe's time was, so the
                    // whole attempt takes as long as that one did.
                    PlainPrefs.wipedForFailuresMs = wiped
                    Thread.sleep(wiped.coerceIn(0, MAX_WIPE_WAIT_MS))
                }
            }
            return Outcome.Wrong
        }
        // Only the real vault's password clears the count of wrong ones. A decoy or duress
        // password leaves it where it was: otherwise whoever holds one could guess at the real
        // password a few at a time for ever, with no lock-out and no wipe.
        if (r.role == Role.MAIN) PlainPrefs.resetFailures() else PlainPrefs.cancelAttempt(attempt)
        when (r.role) {
            Role.MAIN, Role.DECOY -> Session.open(r, alone, SAME_AS_DURESS_MESSAGE.takeIf { sameAsDuress })
            Role.WIPE -> {
                // Duress: destroy the real vault, then quietly open a fresh, empty one under
                // the same password so the person watching just sees an empty vault.
                // The lock screen's header is never missing meanwhile: one no password opens
                // stands in until the new vault's takes its place.
                Aead.wipe(r.master)
                wipeEverything(keepLockScreen = true)
                val fresh = try {
                    VaultManager.create(password, null)
                } catch (_: Exception) {
                    // The lock settings couldn't be saved, so no vault can be made. Everything is
                    // destroyed already: the lock screen stays as it was, every password wrong.
                    return Outcome.Wrong
                }
                Session.open(fresh)
            }
        }
        // The lock settings were replaced by the strictest ones (see PlainPrefs.distrust): the
        // real vault, and only it, says so once it's open.
        if (r.role == Role.MAIN && PlainPrefs.wasDistrusted) {
            Session.current?.store?.let { store ->
                store.problem.value = PlainPrefs.DISTRUSTED_MESSAGE
                PlainPrefs.clearDistrusted()
            }
        }
        return Outcome.Opened
    }

    const val SAME_AS_DURESS_MESSAGE =
        "One of your duress passwords is the same as this vault's password. Typed without the keyfile, it " +
            "acts as the duress password. Remove that duress password in Settings, or change this vault's password."

    /** The longest a wrong password after a wipe waits, whatever the wipe took. */
    private const val MAX_WIPE_WAIT_MS = 10_000L

    /**
     * The lock settings as this session sees and changes them. They belong to the phone, not to
     * one vault, so only the real vault may change them: from a decoy, "wipe after wrong
     * passwords" could otherwise be switched off before guessing at the real password. A decoy
     * is shown the defaults, and what it sets lasts until it locks, like everything else there.
     */
    fun wipeAfterFailures(): Int {
        val s = Session.current
        return if (s == null || s.role == Role.MAIN) PlainPrefs.wipeAfterFailures else s.sessionWipeAfter
    }

    fun setWipeAfterFailures(n: Int) {
        val s = Session.current ?: return
        if (s.role == Role.MAIN) PlainPrefs.wipeAfterFailures = n else s.sessionWipeAfter = n
    }

    fun autoLockSeconds(): Int {
        val s = Session.current
        return if (s == null || s.role == Role.MAIN) PlainPrefs.autoLockSeconds else s.sessionAutoLock
    }

    fun setAutoLockSeconds(n: Int) {
        val s = Session.current ?: return
        if (s.role == Role.MAIN) PlainPrefs.autoLockSeconds = n else s.sessionAutoLock = n
    }

    /**
     * Destroys every vault. With [keepLockScreen] a header no password opens is left in place of
     * the old one, so the lock screen (and the calculator front before it) stay as they were.
     */
    fun wipeEverything(keepCount: Boolean = false, keepLockScreen: Boolean = false) {
        Shares.clear()
        Session.lock()
        VaultManager.wipeAll(keepLockScreen)
        PlainPrefs.mainInContainers = false
        if (!keepCount) PlainPrefs.resetFailures()
    }

    /**
     * Whether this session can tell that [password] is in use already.
     *
     * The real vault knows every slot. A decoy knows only its own (or the one it was
     * given in this session) and the duress passwords added in this session, and checks nothing else: an unlocked decoy must not be a way to try
     * passwords against the real vault, and must answer exactly as a real vault with the same
     * passwords would. One Argon2id run either way, so the time taken is the same too.
     */
    private fun taken(s: Session.Unlocked, password: CharArray, keyfileSecret: ByteArray?): Taken {
        val known = if (s.role == Role.MAIN) (0 until Header.SLOT_COUNT).toList() else listOf(s.slot)
        val p = VaultManager.probe(password, keyfileSecret, known)
        // The lock screen tries every password without the keyfile too, and duress passwords are
        // set without one. So a password given with a keyfile must be free without it as well.
        val bare = if (keyfileSecret != null) VaultManager.probe(password, null, known) else p
        return synchronized(s.sessionDuress) {
            clash(
                slot = s.slot, opens = p.opens, bareOpens = bare.opens, tag = p.tag, bareTag = bare.tag,
                sessionPassword = s.sessionPassword, passwordAlone = s.passwordAlone,
                sessionDuress = s.sessionDuress.map { it.second },
            )
        }
    }

    /**
     * [other]: another password here is the same. [own]: it's this vault's current password,
     * with its keyfile or without. [bareTag]: the password's tag without a keyfile.
     */
    internal class Taken(val other: Boolean, val own: Boolean, val tag: ByteArray, val bareTag: ByteArray)

    /**
     * Whether a password is in use, from what a session knows. [opens] and [tag] are for the
     * password as given (with the keyfile, if there is one); [bareOpens] and [bareTag] for the
     * password alone, the same when there's no keyfile.
     *
     * [passwordAlone] is the tag of this vault's own password without its keyfile, when it has
     * one. Without it, a duress password could be made the same as the real one: the two open
     * different slots (one with the keyfile, one without), so neither looked taken, and typing
     * the real password and forgetting the keyfile then set the duress password off.
     */
    internal fun clash(
        slot: Int, opens: Set<Int>, bareOpens: Set<Int>, tag: ByteArray, bareTag: ByteArray,
        sessionPassword: ByteArray?, passwordAlone: ByteArray?, sessionDuress: List<ByteArray>,
    ): Taken = Taken(
        other = (opens - slot).isNotEmpty() || (bareOpens - slot).isNotEmpty() || sessionDuress.any { it.contentEquals(bareTag) },
        own = (if (sessionPassword != null) sessionPassword.contentEquals(tag) else slot in opens) ||
            (passwordAlone != null && passwordAlone.contentEquals(bareTag)),
        tag = tag, bareTag = bareTag,
    )

    /**
     * Makes a new vault and opens it. With a keyfile, the session also gets the tag of the
     * password alone, as [unlock] gives it, at the cost of one more Argon2id run.
     */
    fun create(password: CharArray, keyfileSecret: ByteArray?) {
        val made = VaultManager.create(password, keyfileSecret)
        val alone = if (keyfileSecret != null) VaultManager.probe(password, null, emptyList()).tag else null
        Session.open(made, alone)
    }

    /** Changes this vault's password. Returns false if another password here is the same. */
    fun changePassword(newPassword: CharArray, keyfileSecret: ByteArray?): Boolean {
        val s = Session.current ?: return true
        val t = taken(s, newPassword, keyfileSecret)
        if (t.other) return false
        if (s.role != Role.MAIN) {
            // A decoy never writes a slot. If it did, whoever holds its password could set it to
            // a guess at the real one, lock, and type the guess: the real vault opening would
            // confirm it, and every try would count as a good unlock, never as a failure. So the
            // new password lasts until the decoy locks, like everything else changed in it, and
            // a guess has to be made at the lock screen, where wrong ones are counted.
            VaultManager.pretendToSetSlot(newPassword, keyfileSecret)
            synchronized(s.sessionDuress) {
                s.sessionPassword?.fill(0)
                s.sessionPassword = t.tag
                s.passwordAlone = t.bareTag.takeIf { keyfileSecret != null }
            }
            s.store.updateSettings { it.copy(usesKeyfile = keyfileSecret != null) }
            return true
        }
        VaultManager.setSlot(s.slot, newPassword, keyfileSecret, s.role, s.master)
        synchronized(s.sessionDuress) { s.passwordAlone = t.bareTag.takeIf { keyfileSecret != null } }
        s.store.updateSettings { it.copy(usesKeyfile = keyfileSecret != null) }
        return true
    }

    enum class Added { OK, IN_USE, NO_SLOTS, FAILED }

    /** Adds a duress password. */
    fun addDuress(password: CharArray, action: String, label: String): Added {
        val s = Session.current ?: return Added.NO_SLOTS
        val t = taken(s, password, null)
        if (t.other || t.own) return Added.IN_USE
        if (s.role != Role.MAIN) {
            // A decoy vault doesn't know where the real slots are, so it must never write the
            // header. It records the entry so the decoy still looks like a fully working vault,
            // with the same limit, for as long as it stays unlocked.
            if (s.store.settings.value.duress.size >= Header.SLOT_COUNT - 1) return Added.NO_SLOTS
            val entry = DuressSlot(-1, action, label)
            VaultManager.pretendToSetSlot(password, null)
            synchronized(s.sessionDuress) { s.sessionDuress += entry to t.tag }
            s.store.updateSettings { it.copy(duress = it.duress + entry) }
            return Added.OK
        }
        val used = s.store.settings.value.duress.map { it.slot }.toSet() + s.slot
        val slot = VaultManager.freeSlot(used) ?: return Added.NO_SLOTS
        val master = Aead.random(Aead.KEY_BYTES)
        val role = if (action == "decoy") Role.DECOY else Role.WIPE
        val main = s.store.storage
        val segs = Session.segments
        var decoyKey: String? = null
        var dir: String? = null
        if (role == Role.DECOY && main is ContainerStorage && segs != null) {
            // The decoy gets its own volume in the containers. The real vault keeps its key, so
            // it can protect the decoy's space and fill it (opened alone, a decoy is read-only).
            ContainerStorage.create(segs, master, migrated = true).close()
            val volume = ContainerStorage.volumeKey(master)
            try {
                main.protect(volume)
            } finally {
                volume.fill(0)
            }
            decoyKey = java.util.Base64.getEncoder().encodeToString(master)
        } else if (role == Role.DECOY) {
            dir = VaultManager.dirFor(master).name
        }
        // The settings entry is saved before the password works. The other way round, a save
        // that failed (or a kill in between) left a working decoy password the real vault knew
        // nothing of: it never protected that decoy and in time wrote over it.
        val entry = DuressSlot(slot, action, label, dir, decoyKey)
        fun undo() {
            if (decoyKey != null && segs != null) runCatching { ContainerStorage.destroy(segs, master) }
            Aead.wipe(master)
        }
        if (!s.store.updateSettings { it.copy(duress = it.duress + entry) }) {
            undo()
            return Added.FAILED
        }
        try {
            VaultManager.setSlot(slot, password, null, role, master)
        } catch (t: Throwable) {
            s.store.updateSettings { it.copy(duress = it.duress - entry) }
            undo()
            throw t
        }
        Aead.wipe(master)
        return Added.OK
    }

    fun removeDuress(d: DuressSlot) {
        val s = Session.current ?: return
        if (s.role == Role.MAIN && d.slot >= 0) {
            VaultManager.clearSlot(d.slot)
            d.dir?.let { java.io.File(VaultManager.vaultsRoot, it).deleteRecursively() }
            val segs = Session.segments
            if (d.master != null && segs != null) {
                val m = java.util.Base64.getDecoder().decode(d.master)
                runCatching { ContainerStorage.destroy(segs, m) }
                m.fill(0)
            }
        }
        synchronized(s.sessionDuress) {
            val i = s.sessionDuress.indexOfFirst { it.first == d }
            if (i >= 0) s.sessionDuress.removeAt(i)
        }
        s.store.updateSettings { st -> st.copy(duress = st.duress - d) }
    }

    /** Whether Settings offers to add files to this duress entry's decoy. */
    fun canFill(d: DuressSlot): Boolean {
        val s = Session.current ?: return false
        if (d.action != "decoy") return false
        return if (s.role == Role.MAIN) d.master != null else d.slot < 0
    }

    /**
     * Adds [files] to a decoy from the session that made it. Returns how many were added, or -1
     * if the decoy couldn't be opened. For an entry a decoy session only pretends to have, the
     * files are read and counted and nothing is kept, like everything else in that session.
     */
    fun fillDecoy(d: DuressSlot, files: List<java.io.File>): Int {
        val s = Session.current ?: return -1
        if (s.role != Role.MAIN) {
            if (d.slot >= 0) return -1
            val buf = ByteArray(64 * 1024)
            return files.count { f -> runCatching { f.inputStream().use { while (it.read(buf) >= 0) Unit } }.isSuccess }.also { buf.fill(0) }
        }
        val decoy = openDecoyForFilling(d) ?: return -1
        try {
            return files.count { f -> runCatching { decoy.importFile(f, null) }.isSuccess }
        } finally {
            decoy.close()
        }
    }
}

/** Opens a decoy that lives in the containers, writable, from the real vault's session. */
fun openDecoyForFilling(d: DuressSlot): VaultStore? {
    val s = Session.current ?: return null
    if (s.role != Role.MAIN) return null
    val segs = Session.segments ?: return null
    val m = java.util.Base64.getDecoder().decode(d.master ?: return null)
    return try {
        val cs = ContainerStorage.open(segs, m, readOnly = false) ?: return null
        // Count the real vault's space too, so filling the decoy never writes over it, and do
        // it before the decoy's own tidying up can write.
        VaultStore(cs, m) {
            val volume = ContainerStorage.volumeKey(s.master)
            try {
                cs.protect(volume)
            } finally {
                volume.fill(0)
            }
        }
    } catch (_: java.io.IOException) {
        // Too damaged to open.
        null
    } catch (_: java.security.GeneralSecurityException) {
        null
    } finally {
        m.fill(0)
    }
}
