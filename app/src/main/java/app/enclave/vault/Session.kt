package app.enclave.vault

import app.enclave.crypto.Aead
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.Base64
import kotlin.concurrent.thread

/** The unlocked vault lives only in memory. Locking zeroes the keys and forgets everything. */
object Session {
    class Unlocked(val role: Role, val slot: Int, val master: ByteArray, val store: VaultStore) {
        /**
         * Duress passwords a decoy session was asked to add, each with a tag of its password. They
         * exist only here: a decoy can't write the header's slots (see [VaultActions.addDuress]).
         */
        val sessionDuress = mutableListOf<Pair<DuressSlot, ByteArray>>()

        /**
         * A tag of the password a decoy session was asked to change to, which it also keeps only
         * here (see [VaultActions.changePassword]). Guarded by [sessionDuress].
         */
        var sessionPassword: ByteArray? = null
    }

    /** Shown while a vault is being prepared or moved into the containers. */
    data class Busy(val title: String, val progress: Migration.Progress? = null)

    private val _state = MutableStateFlow<Unlocked?>(null)
    val state: StateFlow<Unlocked?> = _state

    private val _busy = MutableStateFlow<Busy?>(null)
    val busy: StateFlow<Busy?> = _busy

    /** Why Enclave is about to leave the screen, when it's Enclave that sent the user away. */
    enum class Away { PICKER, HANDOFF }

    @Volatile private var away: Away? = null
    @Volatile private var awaySince = 0L

    /**
     * Call right before sending the user to a system picker or permission screen ([Away.PICKER])
     * or handing a file to another app ([Away.HANDOFF]). Auto-lock then waits a little longer than
     * usual, but never indefinitely: see [lockDelayMs].
     */
    fun leaving(why: Away) {
        away = why
        awaySince = android.os.SystemClock.elapsedRealtime()
    }

    fun cameBack() {
        away = null
    }

    /**
     * How long after Enclave leaves the screen the vault locks, given the usual delay.
     *
     * In a picker Enclave opened, the vault stays open for [PICKER_GRACE_MS] so there's time to
     * choose. After handing a file to another app the usual delay applies, unless that app reads
     * the file straight from the open vault (a big file), which a lock would cut off: then it
     * waits for that link to end, at most [Shares.LIFETIME_MS]. The screen turning off locks at
     * once in every case.
     */
    fun lockDelayMs(usual: Long): Long {
        val why = away
        away = null
        // Only a departure that follows straight on from the call counts.
        if (why == null || android.os.SystemClock.elapsedRealtime() - awaySince > AWAY_WINDOW_MS) return usual
        return when (why) {
            Away.PICKER -> maxOf(usual, PICKER_GRACE_MS)
            Away.HANDOFF -> maxOf(usual, Shares.vaultNeededForMs())
        }
    }

    const val PICKER_GRACE_MS = 5 * 60 * 1000L
    private const val AWAY_WINDOW_MS = 15_000L

    /** The containers, open while a vault is. */
    @Volatile var segments: Segments? = null
        private set

    @Volatile private var stopWork = false
    @Volatile private var worker: Thread? = null

    /**
     * Opens the vault: from the containers if it lives there, moving it there first if it's in the
     * original format, or making it there if it's new. Slow steps run in the background while
     * [busy] says what's happening.
     */
    @Synchronized
    fun open(r: UnlockResult) {
        val segs = Segments(VaultManager.containersDir)
        segments = segs
        stopWork = false
        val old = DirStorage(VaultManager.dirFor(r.master)).takeIf { it.hasVault }

        if (r.role != Role.MAIN) {
            // A decoy. An old-format one keeps its own directory and works as before. One in the
            // containers never writes to them: with only it unlocked, a write could land on the
            // hidden real vault, which this session can't see. Changes look like they work and
            // are kept in memory until it locks, so nothing gives the decoy away.
            val storage = old ?: SessionOnlyStorage(decoyStorage(segs, r.master), VaultManager.scratchDir)
            ready(r, storage)
            return
        }

        val existing = ContainerStorage.open(segs, r.master, readOnly = false)
        when {
            existing != null && existing.migrated -> {
                // A move that finished but was cut off before tidying up.
                old?.deleteAll()
                ready(r, existing)
            }
            old != null -> background(r, "Moving your vault into deniable storage") {
                val target = existing ?: ContainerStorage.create(segs, r.master, migrated = false)
                try {
                    Migration.run(old, target, { p -> _busy.value = Busy("Moving your vault into deniable storage", p) }, { stopWork })
                } catch (t: Throwable) {
                    target.close()
                    throw t
                }
                old.deleteAll()
                target
            }
            existing != null -> {
                // Unfinished move with no old directory left: nothing else to copy from.
                ready(r, existing, finishMove = true)
            }
            // Containers are already here (kept through a wipe): a new vault in them takes no
            // longer than opening one, so no screen that would show a vault was just made.
            segs.all.isNotEmpty() -> ready(r, ContainerStorage.create(segs, r.master, migrated = true))
            else -> background(r, "Preparing secure storage") { ContainerStorage.create(segs, r.master, migrated = true) }
        }
    }

    /** Runs a slow step, then opens the vault. If the move fails, the old format is used as before. */
    private fun background(r: UnlockResult, title: String, work: () -> Storage) {
        _busy.value = Busy(title)
        worker = thread(name = "enclave-storage") {
            try {
                val storage = work()
                if (stopWork) {
                    storage.close()
                    return@thread
                }
                ready(r, storage)
            } catch (_: Migration.Cancelled) {
                // Locked mid-way: the old vault is untouched; the next unlock carries on.
            } catch (t: Throwable) {
                if (!stopWork) {
                    val old = DirStorage(VaultManager.dirFor(r.master))
                    if (old.hasVault) {
                        ready(r, old)
                        _state.value?.store?.problem?.value = "Couldn't move the vault yet (${t.message}). Nothing was lost; it will try again next time."
                    }
                }
            } finally {
                _busy.value = null
                worker = null
                if (stopWork) closeSegments()
            }
        }
    }

    /**
     * A decoy's storage in the containers, opened alone: read-only. One that is missing or too
     * damaged to read is an empty vault, never an error: nothing may tell it from a vault that
     * simply has nothing in it.
     */
    internal fun decoyStorage(segs: Segments, master: ByteArray): Storage =
        runCatching { ContainerStorage.open(segs, master, readOnly = true) }.getOrNull() ?: EmptyStorage()

    /** Keeps the decoys listed in the real vault's settings open, so it never writes over them. */
    internal fun protectDecoys(storage: ContainerStorage, settings: VaultSettings) {
        settings.duress.mapNotNull { it.master }.forEach { m ->
            // One that can't be protected (damaged, or a bad entry) never stops the vault opening.
            runCatching {
                val master = Base64.getDecoder().decode(m)
                val key = ContainerStorage.volumeKey(master)
                master.fill(0)
                try {
                    storage.protect(key)
                } finally {
                    key.fill(0)
                }
            }
        }
    }

    private fun ready(r: UnlockResult, storage: Storage, finishMove: Boolean = false) {
        // Decoys are protected before the real vault can write: opening it tidies up after a
        // crash, and that save would otherwise land on blocks that look free only because the
        // decoys aren't open yet.
        val store = VaultStore(storage, r.master) { settings ->
            if (storage is ContainerStorage && r.role == Role.MAIN) {
                protectDecoys(storage, settings)
                if (finishMove) storage.finishMigration()
            }
        }
        _state.value = Unlocked(r.role, r.slot, r.master, store)
        // Quietly bring old-format files up to date (padding, fixed-size previews).
        thread(name = "enclave-upgrade", isDaemon = true) { runCatching { store.upgradeOldFiles() } }
    }

    @Synchronized
    fun lock() {
        stopWork = true
        val s = _state.value
        _state.value = null
        _busy.value = null
        s?.store?.close()
        s?.master?.let(Aead::wipe)
        s?.sessionDuress?.let { list ->
            synchronized(list) {
                list.forEach { it.second.fill(0) }; list.clear()
                s.sessionPassword?.fill(0); s.sessionPassword = null
            }
        }
        // A move in progress closes the containers itself once it has stopped.
        if (worker == null) closeSegments()
    }

    private fun closeSegments() {
        segments?.close()
        segments = null
    }

    val current get() = _state.value
}
