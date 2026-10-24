package app.enclave.ui.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.colorResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.enclave.disguise.Disguise
import app.enclave.ui.KeyfileRow
import app.enclave.ui.KeyfileState
import app.enclave.ui.PasswordField
import app.enclave.vault.Session
import app.enclave.vault.VaultActions
import app.enclave.vault.VaultManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
private fun CenteredColumn(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize().systemBarsPadding().imePadding(), contentAlignment = Alignment.Center) {
        Column(
            Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) { content() }
    }
}

@Composable
private fun AppBadge() {
    val p = Disguise.current()
    Box(Modifier.size(72.dp).clip(CircleShape), contentAlignment = Alignment.Center) {
        Surface(color = colorResource(p.bg), modifier = Modifier.fillMaxSize()) {}
        Image(painterResource(p.fg), contentDescription = null, modifier = Modifier.fillMaxSize())
    }
}

@Composable
fun SetupScreen() {
    var pw by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val keyfile = remember { KeyfileState() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    CenteredColumn {
        AppBadge()
        Text("Create your vault", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Your password is turned into a 256-bit key with Argon2id. There is no recovery: " +
                "if you forget the password (or lose the keyfile), the data is gone for good.",
            style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        PasswordField(pw, { pw = it }, "Password")
        PasswordField(confirm, { confirm = it }, "Confirm password")
        KeyfileRow(keyfile, allowCreate = true)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            onClick = {
                error = when {
                    pw.length < 8 -> "Use at least 8 characters"
                    pw != confirm -> "Passwords don't match"
                    else -> null
                }
                if (error != null) return@Button
                busy = true
                scope.launch {
                    val r = withContext(Dispatchers.Default) {
                        VaultManager.create(pw.toCharArray(), keyfile.secret)
                    }
                    Session.open(r)
                    if (keyfile.secret != null) Session.current?.store?.updateSettings { it.copy(usesKeyfile = true) }
                    keyfile.clear()
                }
            },
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("Create vault")
        }
    }
}

@Composable
fun LockScreen(onWiped: () -> Unit) {
    var pw by remember { mutableStateOf("") }
    val keyfile = remember { KeyfileState() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var lockout by remember { mutableStateOf(0L) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(lockout) {
        if (lockout > 0) {
            delay(1000); lockout = (lockout - 1000).coerceAtLeast(0)
        }
    }

    CenteredColumn {
        AppBadge()
        Text(Disguise.current().label, style = MaterialTheme.typography.headlineSmall)
        PasswordField(pw, { pw = it }, "Password")
        KeyfileRow(keyfile, allowCreate = false)
        if (lockout > 0) Text("Too many attempts. Try again in ${lockout / 1000 + 1} s", color = MaterialTheme.colorScheme.error)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(
            enabled = !busy && pw.isNotEmpty() && lockout == 0L,
            modifier = Modifier.fillMaxWidth().height(52.dp),
            onClick = {
                busy = true; error = null
                scope.launch {
                    val outcome = withContext(Dispatchers.Default) { VaultActions.unlock(pw.toCharArray(), keyfile.secret) }
                    busy = false
                    when (outcome) {
                        VaultActions.Outcome.Opened -> {
                            pw = ""; keyfile.clear()
                        }
                        VaultActions.Outcome.Wrong -> error = "Wrong password or keyfile"
                        VaultActions.Outcome.Wiped -> onWiped()
                        is VaultActions.Outcome.LockedOut -> lockout = outcome.ms
                    }
                }
            },
        ) {
            if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("Unlock")
        }
        Spacer(Modifier.height(8.dp))
    }
}
