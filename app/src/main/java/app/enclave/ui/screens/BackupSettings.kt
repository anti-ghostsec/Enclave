package app.enclave.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import app.enclave.ui.BrowseMode
import app.enclave.ui.PasswordField
import app.enclave.ui.SectionTitle
import app.enclave.ui.StorageBrowser
import app.enclave.ui.toast
import app.enclave.vault.Backup
import app.enclave.vault.Session
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private sealed interface BackupStep {
    data object AskNewPassword : BackupStep
    class PickFolder(val password: String) : BackupStep
    data object PickFile : BackupStep
    class AskPassword(val file: File) : BackupStep
    class Working(val title: String, val done: Long = 0, val total: Long = 0) : BackupStep
}

/** Settings → Backup: a portable encrypted backup file, and restoring one. */
@Composable
fun BackupSettings(s: Session.Unlocked) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var step by remember { mutableStateOf<BackupStep?>(null) }

    SectionTitle("Backup")
    Text(
        "One encrypted file with everything in this vault, protected only by a password you choose. " +
            "It can be restored on another phone. Unlike the vault, it doesn't need this phone's security chip, " +
            "so it's only as strong as its password.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedButton(onClick = { step = BackupStep.AskNewPassword }) { Text("Create encrypted backup") }
        OutlinedButton(onClick = { step = BackupStep.PickFile }) { Text("Restore from a backup") }
    }

    fun run(title: String, work: ((Long, Long) -> Unit) -> String) {
        step = BackupStep.Working(title)
        scope.launch {
            val message = withContext(Dispatchers.IO) {
                runCatching { work { d, t -> step = BackupStep.Working(title, d, t) } }
                    .getOrElse { it.message ?: "Something went wrong" }
            }
            step = null
            ctx.toast(message)
        }
    }

    when (val st = step) {
        null -> Unit
        BackupStep.AskNewPassword -> NewBackupPasswordDialog(
            onDismiss = { step = null },
            onOk = { step = BackupStep.PickFolder(it) },
        )
        is BackupStep.PickFolder -> StorageBrowser(BrowseMode.FOLDER, onDismiss = { step = null }, confirmLabel = "Save backup here") { dirs ->
            val name = "backup-" + SimpleDateFormat("yyyyMMdd-HHmm", Locale.US).format(Date()) + ".bin"
            val target = app.enclave.ui.freeName(dirs[0], name)
            run("Creating encrypted backup") { progress ->
                Backup.create(s.store, s.master, st.password.toCharArray(), target, progress)
                "Backup saved as ${target.name}"
            }
        }
        BackupStep.PickFile -> StorageBrowser(BrowseMode.FILE, onDismiss = { step = null }) { files ->
            step = BackupStep.AskPassword(files[0])
        }
        is BackupStep.AskPassword -> BackupPasswordDialog(
            onDismiss = { step = null },
            onOk = { pw ->
                val folder = "Restored " + SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date())
                run("Restoring backup") { progress ->
                    val n = Backup.restore(st.file, pw.toCharArray(), s.store, folder, progress)
                    "Restored $n file(s) into “$folder”"
                }
            },
        )
        is BackupStep.Working -> WorkingDialog(st)
    }
}

@Composable
private fun NewBackupPasswordDialog(onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var pw by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val error = when {
        pw.isNotEmpty() && pw.length < 12 -> "Use at least 12 characters"
        confirm.isNotEmpty() && pw != confirm -> "Passwords don't match"
        else -> null
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Backup password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    "Anyone who gets the file can guess passwords as fast as their computer allows, so use a long one you " +
                        "don't use anywhere else. If you forget it, the backup can't be opened by anyone.",
                    style = MaterialTheme.typography.bodySmall,
                )
                PasswordField(pw, { pw = it }, "Password")
                PasswordField(confirm, { confirm = it }, "Confirm password")
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(enabled = pw.length >= 12 && pw == confirm, onClick = { onOk(pw) }) { Text("Choose where to save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun BackupPasswordDialog(onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var pw by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Backup password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Everything in the backup is added to this vault, in a new folder.", style = MaterialTheme.typography.bodySmall)
                PasswordField(pw, { pw = it }, "Password")
            }
        },
        confirmButton = { TextButton(enabled = pw.isNotEmpty(), onClick = { onOk(pw) }) { Text("Restore") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun WorkingDialog(st: BackupStep.Working) {
    val view = LocalView.current
    // The screen turning off locks the vault, which would stop the backup.
    DisposableEffect(Unit) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }
    AlertDialog(
        onDismissRequest = {},
        title = { Text(st.title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (st.total > 0) {
                    LinearProgressIndicator(progress = { (st.done.toFloat() / st.total).coerceIn(0f, 1f) }, modifier = Modifier.fillMaxWidth())
                    Text("${humanSize(st.done)} of ${humanSize(st.total)}")
                } else {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Checking the password (a few seconds)…")
                }
                Text("Keep Enclave open.", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {},
    )
}
