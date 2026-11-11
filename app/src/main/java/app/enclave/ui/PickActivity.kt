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
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.disguise.Disguise
import app.enclave.ui.screens.FilesScreen
import app.enclave.ui.screens.LockScreen
import app.enclave.ui.screens.PickRequest
import app.enclave.ui.screens.ViewerScreen
import app.enclave.vault.Entry
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
        enableEdgeToEdge()
        if (!VaultManager.exists()) return finish()
        val multiple = intent.getBooleanExtra(Intent.EXTRA_ALLOW_MULTIPLE, false)
        setContent {
            EnclaveTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { NoKeyboardLearning {
                    val unlocked by Session.state.collectAsStateWithLifecycle()
                    var viewing by remember { mutableStateOf<Pair<List<Entry>, Int>?>(null) }
                    val s = unlocked
                    var focus by remember { mutableStateOf<String?>(null) }
                    if (s == null) LockScreen()
                    else Box(Modifier.fillMaxSize()) {
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
