package app.enclave.ui

import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
        enableEdgeToEdge()
        setContent {
            EnclaveTheme {
                // Surface supplies the readable text colour for every screen.
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) { Root() }
            }
        }
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
    var exists by remember { mutableStateOf(VaultManager.exists()) }
    var facadePassed by remember { mutableStateOf(false) }

    LaunchedEffect(unlocked) {
        if (unlocked == null) facadePassed = false
        exists = VaultManager.exists()
    }

    val u = unlocked
    when {
        u != null -> HomeScreen(u)
        !exists -> SetupScreen()
        PlainPrefs.calculatorFacade && !facadePassed -> CalculatorScreen(onSecret = { facadePassed = true })
        else -> LockScreen(onWiped = { exists = false })
    }
}
