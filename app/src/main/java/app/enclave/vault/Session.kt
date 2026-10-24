package app.enclave.vault

import app.enclave.crypto.Aead
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlin.concurrent.thread

/** The unlocked vault lives only in memory. Locking zeroes the keys and forgets everything. */
object Session {
    class Unlocked(val role: Role, val slot: Int, val master: ByteArray, val store: VaultStore)

    private val _state = MutableStateFlow<Unlocked?>(null)
    val state: StateFlow<Unlocked?> = _state

    /** Set while the user is in a file picker / cross-profile prompt we opened, so auto-lock waits. */
    @Volatile var awayByChoice = false

    fun open(r: UnlockResult) {
        val store = VaultStore(VaultManager.dirFor(r.master), r.master)
        _state.value = Unlocked(r.role, r.slot, r.master, store)
        // Quietly bring files from older versions up to date (padding, fixed-size previews).
        thread(name = "enclave-upgrade", isDaemon = true) { runCatching { store.upgradeOldFiles() } }
    }

    fun lock() {
        val s = _state.value ?: return
        _state.value = null
        s.store.close()
        Aead.wipe(s.master)
    }

    val current get() = _state.value
}
