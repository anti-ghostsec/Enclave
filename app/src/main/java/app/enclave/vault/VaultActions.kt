package app.enclave.vault

import app.enclave.crypto.Aead

/** Higher-level vault operations used by the UI. All of these are slow (Argon2) — call off the main thread. */
object VaultActions {
    sealed interface Outcome {
        data object Opened : Outcome
        data object Wrong : Outcome
        /** Too many wrong attempts: everything was destroyed. */
        data object Wiped : Outcome
        data class LockedOut(val ms: Long) : Outcome
    }

    fun unlock(password: CharArray, keyfileSecret: ByteArray?): Outcome {
        PlainPrefs.lockoutRemainingMs().let { if (it > 0) return Outcome.LockedOut(it) }
        // Duress passwords never use a keyfile, so if a keyfile is selected (or remembered) and
        // nothing matched, try once more without it.
        val r = VaultManager.unlock(password, keyfileSecret)
            ?: keyfileSecret?.let { VaultManager.unlock(password, null) }
        if (r == null) {
            PlainPrefs.failedAttempts += 1
            PlainPrefs.lastFailureAt = System.currentTimeMillis()
            val max = PlainPrefs.wipeAfterFailures
            if (max > 0 && PlainPrefs.failedAttempts >= max) {
                wipeEverything()
                return Outcome.Wiped
            }
            return Outcome.Wrong
        }
        PlainPrefs.failedAttempts = 0
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
        PlainPrefs.failedAttempts = 0
    }

    fun changePassword(newPassword: CharArray, keyfileSecret: ByteArray?) {
        val s = Session.current ?: return
        VaultManager.setSlot(s.slot, newPassword, keyfileSecret, s.role, s.master)
        s.store.updateSettings { it.copy(usesKeyfile = keyfileSecret != null) }
    }

    /** Adds a duress password. Returns false if all key slots are in use. */
    fun addDuress(password: CharArray, action: String, label: String): Boolean {
        val s = Session.current ?: return false
        if (s.role != Role.MAIN) {
            // A decoy vault doesn't know where the real slots are, so it must never write the
            // header. It records the entry so the decoy still looks like a fully working vault.
            s.store.updateSettings { it.copy(duress = it.duress + DuressSlot(-1, action, label)) }
            return true
        }
        val used = s.store.settings.value.duress.map { it.slot }.toSet() + s.slot
        val slot = VaultManager.freeSlot(used) ?: return false
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
        return true
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
        s.store.updateSettings { st -> st.copy(duress = st.duress - d) }
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
