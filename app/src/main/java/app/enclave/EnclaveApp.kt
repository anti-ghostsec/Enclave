package app.enclave

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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

    override fun onCreate() {
        super.onCreate()
        PlainPrefs.init(this)
        VaultManager.init(this)
        PlainPrefs.forgetOldKeyfileLocation(this)
        app.enclave.disguise.Disguise.moveOldPicker(this)

        // Auto-lock when Enclave leaves the screen. A picker Enclave opened, or a big file being
        // read by another app, gets a longer but always limited wait: see Session.lockDelayMs.
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                handler.removeCallbacks(lock)
                Session.cameBack()
            }

            override fun onStop(owner: LifecycleOwner) {
                handler.removeCallbacks(lock)
                handler.postDelayed(lock, Session.lockDelayMs(PlainPrefs.autoLockSeconds * 1000L))
            }
        })

        // Always lock the moment the screen turns off, and end every link handed to other apps.
        ContextCompat.registerReceiver(this, object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                Session.lock()
                Shares.clear()
            }
        }, IntentFilter(Intent.ACTION_SCREEN_OFF), ContextCompat.RECEIVER_NOT_EXPORTED)
    }
}
