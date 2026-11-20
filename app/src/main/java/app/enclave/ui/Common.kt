package app.enclave.ui

import android.app.Activity
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.view.View
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
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.crypto.Aead
import app.enclave.crypto.Kdf
import app.enclave.disguise.Disguise
import app.enclave.vault.Session
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

/**
 * Messages shown inside Enclave's own window by [MessageHost], never as Android toasts: a toast
 * is drawn outside the window, so screenshots and screen recording catch it, and from Android 12
 * it carries the app's real icon whatever the disguise.
 *
 * Each message belongs to the vault that was unlocked when it was posted (or to the lock screen),
 * and is dropped unshown if that has changed: one vault's file names never reach another's screen.
 */
object Messages {
    class Message(val text: String, val session: Session.Unlocked?)

    val queue = MutableStateFlow<List<Message>>(emptyList())

    fun post(text: String) {
        val m = Message(text, Session.current)
        queue.update { it + m }
    }

    fun done(m: Message) = queue.update { list -> list.filter { it !== m } }
}

/** Shows [msg] inside Enclave's window (see [Messages]). Safe to call from any thread. */
@Suppress("UnusedReceiverParameter")
fun Context.toast(msg: String) = Messages.post(msg)

/** Shows [Messages] one at a time at the bottom of the screen. Place once per activity. */
@Composable
fun MessageHost(modifier: Modifier = Modifier) {
    val host = remember { SnackbarHostState() }
    val queue by Messages.queue.collectAsStateWithLifecycle()
    val unlocked by Session.state.collectAsStateWithLifecycle()
    val next = queue.firstOrNull()
    LaunchedEffect(next, unlocked) {
        if (next == null) return@LaunchedEffect
        if (next.session === unlocked) {
            host.showSnackbar(next.text, withDismissAction = true, duration = SnackbarDuration.Long)
        }
        Messages.done(next)
    }
    SnackbarHost(host, modifier)
}

/** Hands [block] the characters of [s] in an array that is zeroed as soon as it returns. */
inline fun <T> withChars(s: String, block: (CharArray) -> T): T {
    val chars = s.toCharArray()
    try {
        return block(chars)
    } finally {
        chars.fill('\u0000')
    }
}

/**
 * What Enclave's activities do to their window, besides blocking screenshots: no autofill service
 * is offered anything typed or shown in it; from Android 14, accessibility services that aren't
 * tools for people with disabilities can't read it; and from Android 12, other apps' overlays are
 * hidden while it's on screen, so nothing can be drawn over the password field or the files.
 */
fun Activity.protectWindow() {
    window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
    if (Build.VERSION.SDK_INT >= 34) window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
    if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
}

/**
 * Gives this activity's task the disguise's name and icon, for the recent-apps list. Without it
 * the system falls back to the app's own label and icon, "Enclave", whatever the disguise.
 */
@Suppress("DEPRECATION")
fun Activity.showDisguise() {
    val d = Disguise.current()
    runCatching { setTaskDescription(ActivityManager.TaskDescription(d.label, d.icon)) }
}

/** Call right before opening a system picker, so auto-lock allows a few minutes to choose. */
fun leavingOnPurpose() = Session.leaving(Session.Away.PICKER)

/**
 * For names and search words: asks the keyboard not to suggest, correct or learn what's typed,
 * so file names don't end up in its dictionary.
 */
val PrivateKeyboard = KeyboardOptions(autoCorrectEnabled = false)

/**
 * Tells the keyboard not to learn from anything typed inside [content], whichever field it is:
 * every text field in Enclave holds a password, a file name or a search for one.
 */
@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
fun NoKeyboardLearning(content: @Composable () -> Unit) {
    androidx.compose.ui.platform.InterceptPlatformTextInput(
        interceptor = { request, next ->
            next.startInputMethod(
                androidx.compose.ui.platform.PlatformTextInputMethodRequest { info ->
                    request.createInputConnection(info).also {
                        info.imeOptions = info.imeOptions or android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    }
                },
            )
        },
        content = content,
    )
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
                // A name that says nothing about which app the file is for.
                TextButton(onClick = { leavingOnPurpose(); create.launch("data.bin") }) { Text("Create new") }
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
    Session.leaving(Session.Away.HANDOFF)
    runCatching { startActivity(intent) }.onFailure {
        Session.cameBack()
        toast("No app can open this")
    }
}
