package app.enclave.vault

import app.enclave.crypto.Aead
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.Base64
import kotlin.concurrent.thread

/** The unlocked vault lives only in memory. Locking zeroes the keys and forgets everything. */
object Session {
    class Unlocked(val role: Role, val slot: Int, val master: ByteArray, val store: VaultStore)

    /** Shown while a vault is being prepared or moved into the containers. */
    data class Busy(val title: String, val progress: Migration.Progress? = null)

    private val _state = MutableStateFlow<Unlocked?>(null)
    val state: StateFlow<Unlocked?> = _state

    private val _busy = MutableStateFlow<Busy?>(null)
    val busy: StateFlow<Busy?> = _busy

    /** Set while the user is in a file picker / cross-profile prompt we opened, so auto-lock waits. */
    @Volatile var awayByChoice = false

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
            // containers opens read-only: writing with only it unlocked could overwrite the
            // hidden real vault, which this session can't see.
            val storage = old ?: ContainerStorage.open(segs, r.master, readOnly = true) ?: EmptyStorage()
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
                existing.finishMigration()
                ready(r, existing)
            }
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

    private fun ready(r: UnlockResult, storage: Storage) {
        val store = VaultStore(storage, r.master)
        if (storage is ContainerStorage && r.role == Role.MAIN) {
            // Keep decoys in the containers open, so this vault never writes over them.
            store.settings.value.duress.mapNotNull { it.master }.forEach { m ->
                val key = Base64.getDecoder().decode(m)
                storage.protect(ContainerStorage.volumeKey(key))
                key.fill(0)
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
        // A move in progress closes the containers itself once it has stopped.
        if (worker == null) closeSegments()
    }

    private fun closeSegments() {
        segments?.close()
        segments = null
    }

    val current get() = _state.value
}
