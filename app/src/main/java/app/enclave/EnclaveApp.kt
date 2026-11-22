package app.enclave

import android.app.Activity
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import app.enclave.vault.PlainPrefs
import app.enclave.vault.Session
import app.enclave.vault.Shares
import app.enclave.vault.VaultManager

class EnclaveApp : Application() {
    private val handler = Handler(Looper.getMainLooper())
    private val lock = Runnable { Session.lock() }

    /** When the vault is due to lock, in time since boot (which keeps counting in sleep); 0 = not set. */
    @Volatile private var lockDue = 0L

    /**
     * The lock deadline set when Enclave last left the screen from its own main screen, and the
     * vault it was for. Coming back only to the picker (which any app can open) doesn't move it
     * later: see onStop.
     */
    @Volatile private var heldDue = 0L
    @Volatile private var heldFor: java.lang.ref.WeakReference<Session.Unlocked>? = null

    /** Whether Enclave's main screen was shown since it last left the screen. */
    @Volatile private var mainShown = false

    /** How far time since boot was ahead of time awake when Enclave left the screen; -1 = not set. */
    @Volatile private var sleptAtStop = -1L

    /** Time the phone has spent asleep since boot. It only grows while the screen is off. */
    private fun slept() = android.os.SystemClock.elapsedRealtime() - android.os.SystemClock.uptimeMillis()

    private fun lockNow() {
        Session.lock()
        Shares.clear()
        Session.closeFront()
    }

    override fun onCreate() {
        super.onCreate()
        PlainPrefs.init(this)
        VaultManager.init(this)
        PlainPrefs.forgetOldKeyfileLocation(this)
        app.enclave.disguise.Disguise.moveOldPicker(this)

        registerActivityLifecycleCallbacks(object : ActivityLifecycleCallbacks {
            override fun onActivityStarted(activity: Activity) {
                if (activity is app.enclave.ui.MainActivity) mainShown = true
            }
            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        })

        // Auto-lock when Enclave leaves the screen. A picker Enclave opened, or a big file being
        // read by another app, gets a longer but always limited wait: see Session.lockDelayMs.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                handler.removeCallbacks(lock)
                // The timer below doesn't run while the phone sleeps or Enclave is frozen in the
                // background. If the time is up, lock now, before anything is shown.
                val due = lockDue
                lockDue = 0
                if (due != 0L && android.os.SystemClock.elapsedRealtime() >= due) Session.lock()
                // The "screen off" message can be dropped while Enclave is frozen in the
                // background. If the phone slept since Enclave left, the screen was off: lock as
                // that message would have.
                val before = sleptAtStop
                sleptAtStop = -1
                if (before >= 0 && slept() - before > 1000) lockNow()
                Session.cameBack()
            }

            override fun onStop(owner: LifecycleOwner) {
                handler.removeCallbacks(lock)
                sleptAtStop = slept()
                // Leaving because the screen turned off: don't wait for the message.
                val power = getSystemService(android.os.PowerManager::class.java)
                if (power != null && !power.isInteractive) lockNow()
                val onPurpose = Session.leavingOnPurpose()
                // With no vault open the lock screen starts over, unless Enclave itself sent the
                // user away to choose a keyfile.
                if (Session.current == null && Session.busy.value == null && !onPurpose) Session.closeFront()
                val delay = Session.lockDelayMs(app.enclave.vault.VaultActions.autoLockSeconds() * 1000L)
                val now = android.os.SystemClock.elapsedRealtime()
                var due = now + delay
                // Another app can open the picker and send it away again as often as it likes.
                // If only the picker was shown since the last deadline was set, for the same
                // vault, and the user didn't pick anything there, this can't move it later:
                // otherwise the vault would never auto-lock.
                val s = Session.current
                if (s != null && !mainShown && !onPurpose && heldDue != 0L && heldFor?.get() === s) {
                    due = minOf(due, heldDue)
                } else {
                    heldDue = due
                    heldFor = s?.let { java.lang.ref.WeakReference(it) }
                }
                mainShown = false
                lockDue = due
                handler.postDelayed(lock, (due - now).coerceAtLeast(0))
            }
        })

        // Always lock the moment the screen turns off, and end every link handed to other apps.
        ContextCompat.registerReceiver(this, object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                Session.lock()
                Shares.clear()
                Session.closeFront()
            }
        }, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
    }
}
