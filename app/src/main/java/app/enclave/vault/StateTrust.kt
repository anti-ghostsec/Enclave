package app.enclave.vault

/**
 * Decides what to make of the lock-out state file when Enclave loads it (see [PlainPrefs]). Kept
 * apart from the keystore and the files, so the rules can be tested on their own.
 *
 * Only positive evidence counts as tampering: the file missing while a vault exists, or every
 * state key rejecting it as sealed by another key. Anything else that goes wrong (the keystore
 * busy, StrongBox or the TEE not answering, a read error) is a passing fault: nothing is saved
 * over the file, and it's read again later. Even positive evidence is acted on only once it's
 * seen again on a later start of the app, or [CONFIRM_MS] after it was first seen; until then
 * no password is tried at all, because no attempt could be counted.
 */
internal object StateTrust {
    /** What reading the state file found. */
    enum class Found {
        /** There's no state file. */
        MISSING,
        /** A state key opened it and it was read. */
        OPENED,
        /** No state key opens it: each rejected it as sealed by another key, or there's none. */
        REJECTED,
        /** It couldn't be read for some other reason, which may pass. */
        ERROR,
    }

    enum class Action {
        /** Use what was read. */
        USE,
        /** No vault, so nothing to protect: start with no settings. */
        START_EMPTY,
        /** Settings from before 0.4.0, kept in plain preferences: move them over. */
        MOVE_OLD,
        /** Try again later; save nothing over the file meanwhile. */
        RETRY,
        /** Looks tampered with: wait for it to be seen again, saving nothing and trying no password. */
        SUSPECT,
        /** Confirmed: put the strictest lock-out in place. */
        DISTRUST,
    }

    /** How long the same evidence must last within one run of the app before it's acted on. */
    const val CONFIRM_MS = 2 * 60 * 1000L

    /**
     * @param vault whether a vault header exists.
     * @param stateKeys whether any state key exists; null if the keystore couldn't say.
     * @param oldPreferences whether plain preferences that a version before 0.4.0 could have
     *   written are there (and nothing that a later version would have added to them).
     * @param suspectedBefore whether this was already suspected by an earlier run of the app.
     * @param suspectedForMs how long this run has suspected it; negative if it hasn't yet.
     */
    fun decide(
        found: Found,
        vault: Boolean,
        stateKeys: Boolean?,
        oldPreferences: Boolean,
        suspectedBefore: Boolean,
        suspectedForMs: Long,
    ): Action = when (found) {
        Found.OPENED -> Action.USE
        Found.ERROR -> Action.RETRY
        Found.MISSING, Found.REJECTED -> when {
            !vault -> Action.START_EMPTY
            found == Found.MISSING && stateKeys == null -> Action.RETRY
            // Versions before 0.4.0 had no state file and no state key. Someone who can only
            // write Enclave's files can't delete its keys, so with any key there a missing file
            // was deleted; and one who can use the keys could seal any state they liked anyway.
            found == Found.MISSING && stateKeys == false && oldPreferences -> Action.MOVE_OLD
            suspectedBefore || suspectedForMs >= CONFIRM_MS -> Action.DISTRUST
            else -> Action.SUSPECT
        }
    }

    /**
     * The count of wrong passwords [PlainPrefs.distrust] starts from, given the wipe setting it
     * puts in place. The first time, a few wrong passwords are left before the wipe, so someone
     * whose file was simply damaged isn't one typo from losing everything. If it happens again
     * before the real password has been typed, none are left beyond the next: otherwise putting
     * an old copy back over and over would give a few more guesses each time.
     */
    fun distrustCount(wipeAfter: Int, distrustedBefore: Boolean): Int =
        if (distrustedBefore) wipeAfter - 1 else wipeAfter - FIRST_MARGIN

    /** Wrong passwords left before the wipe the first time: the third one wipes. */
    const val FIRST_MARGIN = 3

    /** The settings versions before 0.4.0 kept in plain preferences, and nothing else. */
    val OLD_PREFERENCE_KEYS = setOf(
        "auto_lock", "calc_facade", "calc_hash", "calc_salt", "disguise", "failed", "failed_at", "keyfile_uri", "wipe_after",
    )

    /** Whether [keys] could have been written by a version before 0.4.0. */
    fun looksOld(keys: Set<String>) = keys.isNotEmpty() && OLD_PREFERENCE_KEYS.containsAll(keys)
}
