package app.enclave.ui

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.ui.screens.BusyScreen
import app.enclave.ui.screens.CalculatorScreen
import app.enclave.ui.screens.HomeScreen
import app.enclave.ui.screens.LockScreen
import app.enclave.ui.screens.SetupScreen
import app.enclave.vault.PlainPrefs
import app.enclave.vault.Session
import app.enclave.vault.VaultManager

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no screen recording, blank preview in the recent-apps list.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        protectWindow()
        showDisguise()
        enableEdgeToEdge()
        setContent {
            EnclaveTheme {
                // Surface supplies the readable text colour for every screen.
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    NoKeyboardLearning {
                        Box(Modifier.fillMaxSize()) {
                            Root()
                            MessageHost(Modifier.align(Alignment.BottomCenter).systemBarsPadding().imePadding().padding(bottom = 72.dp))
                        }
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // The disguise may have changed in Settings.
        showDisguise()
    }
}

@Composable
fun EnclaveTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val scheme = if (Build.VERSION.SDK_INT >= 31) dynamicDarkColorScheme(ctx)
    else darkColorScheme(primary = Color(0xFF8EA2FF))
    MaterialTheme(colorScheme = scheme, content = content)
}

@Composable
private fun Root() {
    val unlocked by Session.state.collectAsStateWithLifecycle()
    val busy by Session.busy.collectAsStateWithLifecycle()
    var exists by remember { mutableStateOf(VaultManager.exists()) }
    // The code counts only until the lock screen next starts over (see Session.front). Read
    // while this screen is stopped too, so the calculator is back before it's shown again.
    val front by Session.front.collectAsState()
    var passedAt by remember { mutableStateOf(-1) }
    val facadePassed = passedAt == front

    LaunchedEffect(unlocked) {
        if (unlocked == null) passedAt = -1
        exists = VaultManager.exists()
    }

    val u = unlocked
    val b = busy
    when {
        // Keyed by the session, so nothing remembered for one vault survives into the next.
        u != null -> key(u) { HomeScreen(u) }
        b != null -> BusyScreen(b)
        // The calculator front comes before everything else, the offer to create a vault too:
        // whatever happened to the vault, a calculator icon opens on a calculator.
        PlainPrefs.calculatorFacade && !facadePassed -> CalculatorScreen(onSecret = { passedAt = front })
        !exists -> SetupScreen()
        // Keyed, so a typed password or a chosen keyfile doesn't outlive the front closing.
        else -> key(front) { LockScreen() }
    }
}
