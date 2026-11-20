package app.enclave.ui

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.disguise.Disguise
import app.enclave.ui.screens.CalculatorScreen
import app.enclave.ui.screens.FilesScreen
import app.enclave.ui.screens.LockScreen
import app.enclave.ui.screens.PickRequest
import app.enclave.ui.screens.ViewerScreen
import app.enclave.vault.Entry
import app.enclave.vault.PlainPrefs
import app.enclave.vault.Session
import app.enclave.vault.Shares
import app.enclave.vault.VaultManager

/**
 * Lets another app (a browser, a forum, a chat) pick a file straight from the vault, like it
 * would from Files. Off unless turned on in Settings. Enclave must be unlocked first; the app
 * only gets the files you tap, through links that end when the screen turns off.
 *
 * Other apps reach it through one alias per disguise (see the manifest), so in their list of
 * places to pick from it carries the disguise's name and icon, never "Enclave" under a disguise.
 */
class PickActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        // Its task is usually the calling app's, so it leaves that task's name and icon alone.
        protectWindow()
        enableEdgeToEdge()
        if (!VaultManager.exists()) return finish()
        val multiple = intent.getBooleanExtra(Intent.EXTRA_ALLOW_MULTIPLE, false)
        setContent {
            EnclaveTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { NoKeyboardLearning {
                    val unlocked by Session.state.collectAsStateWithLifecycle()
                    val s = unlocked
                    // Remembered per unlocked vault: after a lock, the file that was open (and
                    // its name) must not be there for whichever vault is unlocked next.
                    var viewing by remember(s) { mutableStateOf<Pair<List<Entry>, Int>?>(null) }
                    var focus by remember(s) { mutableStateOf<String?>(null) }
                    // With the calculator front on, it stands in front of the password here too,
                    // again after every lock.
                    var facadePassed by remember { mutableStateOf(false) }
                    LaunchedEffect(s) { if (s == null) facadePassed = false }
                    if (s == null) {
                        if (PlainPrefs.calculatorFacade && !facadePassed) CalculatorScreen(onSecret = { facadePassed = true })
                        else LockScreen()
                    } else key(s) {
                        // Keyed by the session, like the main screen: the lock in between can be
                        // missed while this screen is stopped, and nothing remembered for one vault
                        // (the open folder, a search) may be shown for the next.
                        Box(Modifier.fillMaxSize()) {
                            ShareHost(s.store)
                            Box(Modifier.systemBarsPadding()) {
                                FilesScreen(
                                    s.store,
                                    onView = { items, i -> viewing = items to i },
                                    pick = PickRequest(multiple) { picked -> deliver(picked) },
                                    active = viewing == null,
                                    focus = focus,
                                )
                            }
                            viewing?.let { (items, start) ->
                                ViewerScreen(s.store, items, start, onClose = { last -> focus = last?.id; viewing = null })
                            }
                        }
                    }
                    Box(Modifier.fillMaxSize()) {
                        MessageHost(Modifier.align(Alignment.BottomCenter).systemBarsPadding().imePadding())
                    }
                } }
            }
        }
    }

    private fun deliver(picked: List<Entry>) {
        val store = Session.current?.store ?: return
        val files = picked.filter { !it.folder }
        if (files.isEmpty()) return
        val uris = files.map { Shares.create(this, store, it) }
        val result = Intent().setData(uris[0]).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        result.clipData = ClipData.newRawUri(files[0].name, uris[0]).apply { uris.drop(1).forEach { addItem(ClipData.Item(it)) } }
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        fun isEnabled(c: Context) = Disguise.pickerEnabled(c)

        fun setEnabled(c: Context, on: Boolean) = Disguise.setPickerEnabled(c, on)
    }
}
