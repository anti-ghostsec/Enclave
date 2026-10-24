package app.enclave.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import app.enclave.crypto.Aead
import app.enclave.crypto.Kdf
import app.enclave.vault.Session

fun Context.toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

/** Call right before opening a system picker so auto-lock doesn't fire while it's open. */
fun leavingOnPurpose() {
    Session.awayByChoice = true
}

@Composable
fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier.fillMaxWidth(),
) {
    var show by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        modifier = modifier,
        visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
        trailingIcon = {
            IconButton(onClick = { show = !show }) {
                Icon(if (show) Icons.Default.VisibilityOff else Icons.Default.Visibility, contentDescription = "Show")
            }
        },
    )
}

class KeyfileState {
    var secret by mutableStateOf<ByteArray?>(null)
    var label by mutableStateOf<String?>(null)

    fun load(input: () -> java.io.InputStream, name: String): Boolean = runCatching {
        val s = Kdf.keyfileSecret(input())
        clear()
        secret = s; label = name
    }.isSuccess

    fun clear() {
        secret?.fill(0); secret = null; label = null
    }
}

/**
 * Pick an existing keyfile (any file works: a photo, a song...) or create a new random one.
 * Enclave never remembers where the keyfile is.
 */
@Composable
fun KeyfileRow(state: KeyfileState, allowCreate: Boolean) {
    val ctx = LocalContext.current
    var menu by remember { mutableStateOf(false) }
    var browsing by remember { mutableStateOf(false) }

    val onPicked: (Uri?) -> Unit = { uri ->
        if (uri != null && !state.load({ ctx.contentResolver.openInputStream(uri)!! }, "Keyfile selected")) ctx.toast("Couldn't read that file")
    }
    val pickPhoto = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia(), onPicked)
    val create = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        if (uri != null) runCatching {
            val bytes = Aead.random(64)
            ctx.contentResolver.openOutputStream(uri)!!.use { it.write(bytes) }
            bytes.fill(0)
            if (!state.load({ ctx.contentResolver.openInputStream(uri)!! }, "New keyfile saved")) error("unreadable")
        }.onFailure { ctx.toast("Couldn't save the keyfile") }
    }

    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box {
                AssistChip(
                    onClick = { menu = true },
                    label = { Text(state.label ?: "Keyfile (optional)") },
                    leadingIcon = { Icon(Icons.Default.Key, null) },
                )
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(
                        text = { Text("Browse folders") },
                        onClick = { menu = false; browsing = true },
                    )
                    DropdownMenuItem(
                        text = { Text("Photos") },
                        onClick = {
                            menu = false; leavingOnPurpose()
                            pickPhoto.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                        },
                    )
                }
            }
            if (state.secret != null) {
                TextButton(onClick = { state.clear() }) { Text("Remove") }
            } else if (allowCreate) {
                TextButton(onClick = { leavingOnPurpose(); create.launch("enclave.key") }) { Text("Create new") }
            }
        }
    }
    if (browsing) {
        StorageBrowser(BrowseMode.FILE, onDismiss = { browsing = false }) { files ->
            browsing = false
            if (!state.load({ files[0].inputStream() }, "Keyfile selected")) ctx.toast("Couldn't read that file")
        }
    }
}

@Composable
fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(top = 20.dp, bottom = 8.dp),
    )
}

fun Context.openExternally(intent: Intent) {
    leavingOnPurpose()
    runCatching { startActivity(intent) }.onFailure {
        Session.awayByChoice = false
        toast("No app can open this")
    }
}
