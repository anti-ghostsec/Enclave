package app.enclave.vault

import app.enclave.crypto.Aead

/** Higher-level vault operations used by the UI. All of these are slow (Argon2) — call off the main thread. */
object VaultActions {
    sealed interface Outcome {
        data object Opened : Outcome
        data object Wrong : Outcome
        data class LockedOut(val ms: Long) : Outcome
    }

    fun unlock(password: CharArray, keyfileSecret: ByteArray?): Outcome {
        PlainPrefs.lockoutRemainingMs().let { if (it > 0) return Outcome.LockedOut(it) }
        // Duress passwords never use a keyfile, so with a keyfile selected the password is also
        // tried without it. Both are always tried, so a duress password takes exactly as long as
        // the real one and the time taken gives nothing away.
        val withKeyfile = VaultManager.unlock(password, keyfileSecret)
        val without = if (keyfileSecret != null) VaultManager.unlock(password, null) else null
        val r = withKeyfile ?: without
        if (withKeyfile != null) without?.master?.let(Aead::wipe)
        if (r == null) {
            PlainPrefs.recordFailure()
            val max = PlainPrefs.wipeAfterFailures
            if (max > 0 && PlainPrefs.failedAttempts >= max) {
                // Destroy everything, but look exactly as before: the lock screen stays, and
                // from now on every password is simply "wrong".
                wipeEverything()
                VaultManager.createUnopenable()
            }
            return Outcome.Wrong
        }
        PlainPrefs.resetFailures()
        when (r.role) {
            Role.MAIN, Role.DECOY -> Session.open(r)
            Role.WIPE -> {
                // Duress: destroy the real vault, then quietly open a fresh, empty one under
                // the same password so the person watching just sees an empty vault.
                Aead.wipe(r.master)
                wipeEverything()
                Session.open(VaultManager.create(password, null))
            }
        }
        return Outcome.Opened
    }

    fun wipeEverything() {
        Shares.clear()
        Session.lock()
        VaultManager.wipeAll()
        PlainPrefs.resetFailures()
    }

    /**
     * Whether this session can tell that [password] is in use already.
     *
     * The real vault knows every slot. A decoy knows only its own and the duress passwords added
     * in this session, and checks nothing else: an unlocked decoy must not be a way to try
     * passwords against the real vault, and must answer exactly as a real vault with the same
     * passwords would. One Argon2id run either way, so the time taken is the same too.
     */
    private fun taken(s: Session.Unlocked, password: CharArray, keyfileSecret: ByteArray?): Pair<Boolean, VaultManager.Probe> {
        val known = if (s.role == Role.MAIN) (0 until Header.SLOT_COUNT).toList() else listOf(s.slot)
        val p = VaultManager.probe(password, keyfileSecret, known)
        val other = (p.opens - s.slot).isNotEmpty() || synchronized(s.sessionDuress) { s.sessionDuress.any { it.second.contentEquals(p.tag) } }
        return other to p
    }

    /** Changes this vault's password. Returns false if another password here is the same. */
    fun changePassword(newPassword: CharArray, keyfileSecret: ByteArray?): Boolean {
        val s = Session.current ?: return true
        if (taken(s, newPassword, keyfileSecret).first) return false
        VaultManager.setSlot(s.slot, newPassword, keyfileSecret, s.role, s.master)
        s.store.updateSettings { it.copy(usesKeyfile = keyfileSecret != null) }
        return true
    }

    enum class Added { OK, IN_USE, NO_SLOTS }

    /** Adds a duress password. */
    fun addDuress(password: CharArray, action: String, label: String): Added {
        val s = Session.current ?: return Added.NO_SLOTS
        val (other, probe) = taken(s, password, null)
        if (other || s.slot in probe.opens) return Added.IN_USE
        if (s.role != Role.MAIN) {
            // A decoy vault doesn't know where the real slots are, so it must never write the
            // header. It records the entry so the decoy still looks like a fully working vault,
            // with the same limit, for as long as it stays unlocked.
            if (s.store.settings.value.duress.size >= Header.SLOT_COUNT - 1) return Added.NO_SLOTS
            val entry = DuressSlot(-1, action, label)
            // The same work a real vault does to write the slot, so this takes as long.
            VaultManager.probe(password, null, emptyList())
            synchronized(s.sessionDuress) { s.sessionDuress += entry to probe.tag }
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
            main.protect(ContainerStorage.volumeKey(master))
            decoyKey = java.util.Base64.getEncoder().encodeToString(master)
        } else if (role == Role.DECOY) {
            dir = VaultManager.dirFor(master).name
        }
        VaultManager.setSlot(slot, password, null, role, master)
        Aead.wipe(master)
        s.store.updateSettings { it.copy(duress = it.duress + DuressSlot(slot, action, label, dir, decoyKey)) }
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
        // Count the real vault's space too, so filling the decoy never writes over it.
        cs.protect(ContainerStorage.volumeKey(s.master))
        VaultStore(cs, m)
    } finally {
        m.fill(0)
    }
}
