package app.enclave.ui.screens

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Rect
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.colorResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.crypto.HardwareKey
import app.enclave.disguise.Disguise
import app.enclave.ui.KeyfileRow
import app.enclave.ui.Opener
import app.enclave.ui.PickActivity
import app.enclave.ui.ShareAppsEditor
import app.enclave.ui.KeyfileState
import app.enclave.ui.PasswordField
import app.enclave.ui.SectionTitle
import app.enclave.ui.leavingOnPurpose
import app.enclave.ui.toast
import app.enclave.vault.PlainPrefs
import app.enclave.vault.Session
import app.enclave.vault.VaultActions
import app.enclave.vault.VaultManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SettingsScreen(s: Session.Unlocked, disguiseLabel: String) {
    val ctx = LocalContext.current
    val settings by s.store.settings.collectAsStateWithLifecycle()
    var changePw by remember { mutableStateOf(false) }
    var addDuress by remember { mutableStateOf(false) }
    var wipeAll by remember { mutableStateOf(false) }
    var codeDialog by remember { mutableStateOf(false) }
    var disguise by remember { mutableStateOf(Disguise.current()) }
    var facade by remember { mutableStateOf(PlainPrefs.calculatorFacade) }
    var autoLock by remember { mutableIntStateOf(PlainPrefs.autoLockSeconds) }
    var wipeAfter by remember { mutableIntStateOf(PlainPrefs.wipeAfterFailures) }
    val strongBox = remember { HardwareKey.isStrongBox() }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
        Card(Modifier.fillMaxWidth().padding(top = 8.dp)) {
            Row(Modifier.padding(16.dp)) {
                Icon(Icons.Default.Shield, null, tint = MaterialTheme.colorScheme.primary)
                Column(Modifier.padding(start = 12.dp)) {
                    Text("How your data is protected", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "• Files: AES-256-GCM, a fresh key for every file\n" +
                            "• Password → key: Argon2id, 64 MiB memory, 3 passes" +
                            (if (settings.usesKeyfile) " + your keyfile" else "") + "\n" +
                            "• Vault header sealed by a hardware key (" + (if (strongBox) "StrongBox chip" else "secure TEE") + ")\n" +
                            "• Quantum-resistant: only 256-bit symmetric crypto, no RSA/ECC anywhere\n" +
                            "• Nothing decrypted is ever written to storage",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }

        SectionTitle("Password")
        OutlinedButton(onClick = { changePw = true }) { Text("Change password or keyfile") }

        SectionTitle("Duress passwords")
        Text(
            "A second password that looks like it works. Use it if you're ever forced to unlock.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        settings.duress.forEach { d ->
            ListItem(
                headlineContent = { Text(d.label.ifBlank { "Duress password" }) },
                supportingContent = { Text(if (d.action == "decoy") "Opens a decoy vault" else "Silently wipes everything, then opens an empty vault") },
                trailingContent = { IconButton(onClick = { VaultActions.removeDuress(d) }) { Icon(Icons.Default.Delete, "Remove") } },
            )
        }
        OutlinedButton(onClick = { addDuress = true }) { Text("Add duress password") }

        SectionTitle("Disguise")
        Text(
            "Changes the name and icon in your app drawer. Currently: $disguiseLabel. The launcher can take a few seconds to update.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        FlowRow(Modifier.padding(vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Disguise.presets.forEach { p ->
                val selected = p == disguise
                Surface(
                    shape = RoundedCornerShape(16.dp),
                    border = if (selected) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null,
                    modifier = Modifier.width(88.dp).clickable {
                        Disguise.apply(ctx, p); disguise = p
                    },
                ) {
                    Column(Modifier.padding(8.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Box(Modifier.size(52.dp).clip(CircleShape)) {
                            Surface(color = colorResource(p.bg), modifier = Modifier.fillMaxSize()) {}
                            Image(painterResource(p.fg), null, Modifier.fillMaxSize())
                        }
                        Text(p.label, style = MaterialTheme.typography.labelSmall, textAlign = TextAlign.Center, maxLines = 2)
                    }
                }
            }
        }
        ListItem(
            headlineContent = { Text("Open as a working calculator") },
            supportingContent = { Text("The app opens as a real calculator. Type your secret code and press = to reach the lock screen.") },
            trailingContent = {
                Switch(checked = facade, onCheckedChange = { on ->
                    if (on) codeDialog = true else { PlainPrefs.calculatorFacade = false; facade = false }
                })
            },
        )
        if (facade) TextButton(onClick = { codeDialog = true }) { Text("Change calculator code") }
        CustomShortcut()

        OpeningSettings(s)

        SectionTitle("Auto-lock")
        Text("Enclave always locks when the screen turns off. When you switch to another app:", style = MaterialTheme.typography.bodySmall)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(0 to "Immediately", 30 to "30 s", 60 to "1 min", 300 to "5 min").forEach { (v, label) ->
                FilterChip(selected = autoLock == v, onClick = { PlainPrefs.autoLockSeconds = v; autoLock = v }, label = { Text(label) })
            }
        }

        SectionTitle("Wipe after wrong passwords")
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(0 to "Never", 5 to "5", 10 to "10", 20 to "20").forEach { (v, label) ->
                FilterChip(selected = wipeAfter == v, onClick = { PlainPrefs.wipeAfterFailures = v; wipeAfter = v }, label = { Text(label) })
            }
        }

        SectionTitle("Danger zone")
        OutlinedButton(onClick = { wipeAll = true }) { Text("Wipe everything now", color = MaterialTheme.colorScheme.error) }
        Box(Modifier.size(32.dp))
    }

    if (changePw) ChangePasswordDialog(onDone = { changePw = false })
    if (addDuress) AddDuressDialog(onDone = { addDuress = false })
    if (codeDialog) CalculatorCodeDialog(
        onDismiss = { codeDialog = false },
        onSet = { PlainPrefs.setCalculatorCode(it); PlainPrefs.calculatorFacade = true; facade = true; codeDialog = false },
    )
    if (wipeAll) WipeDialog(onDismiss = { wipeAll = false })
}

@Composable
private fun ChangePasswordDialog(onDone: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var confirm by remember { mutableStateOf("") }
    val keyfile = remember { KeyfileState() }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        title = { Text("New password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                PasswordField(pw, { pw = it }, "New password")
                PasswordField(confirm, { confirm = it }, "Confirm")
                KeyfileRow(keyfile, allowCreate = true)
                Text("Leave the keyfile empty to stop using one.", style = MaterialTheme.typography.bodySmall)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (busy) CircularProgressIndicator()
            }
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = {
                error = when {
                    pw.length < 8 -> "Use at least 8 characters"
                    pw != confirm -> "Passwords don't match"
                    else -> null
                }
                if (error != null) return@TextButton
                busy = true
                scope.launch {
                    val clash = withContext(Dispatchers.Default) { VaultManager.unlock(pw.toCharArray(), keyfile.secret) }
                    if (clash != null && clash.slot != Session.current?.slot) {
                        clash.master.fill(0)
                        busy = false; error = "Choose a different password"
                        return@launch
                    }
                    clash?.master?.fill(0)
                    withContext(Dispatchers.Default) { VaultActions.changePassword(pw.toCharArray(), keyfile.secret) }
                    keyfile.clear()
                    ctx.toast("Password changed")
                    onDone()
                }
            }) { Text("Save") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDone) { Text("Cancel") } },
    )
}

@Composable
private fun AddDuressDialog(onDone: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var label by remember { mutableStateOf("") }
    var pw by remember { mutableStateOf("") }
    var action by remember { mutableStateOf("decoy") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDone() },
        title = { Text("Add duress password") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(label, { label = it }, label = { Text("Name (only you see this)") }, singleLine = true)
                PasswordField(pw, { pw = it }, "Duress password")
                listOf(
                    "decoy" to "Open a decoy vault — put some harmless files in it so it looks real",
                    "wipe" to "Wipe everything, then show an empty vault",
                ).forEach { (v, text) ->
                    Row(Modifier.selectable(selected = action == v, onClick = { action = v }), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = action == v, onClick = { action = v })
                        Text(text, style = MaterialTheme.typography.bodySmall)
                    }
                }
                Text("Duress passwords don't use a keyfile, so they work even if you're made to unlock without one.", style = MaterialTheme.typography.bodySmall)
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (busy) CircularProgressIndicator()
            }
        },
        confirmButton = {
            TextButton(enabled = !busy && pw.length >= 4, onClick = {
                busy = true; error = null
                scope.launch {
                    val clash = withContext(Dispatchers.Default) { VaultManager.unlock(pw.toCharArray(), null) }
                    if (clash != null) {
                        clash.master.fill(0)
                        busy = false; error = "That password is already in use"
                        return@launch
                    }
                    val ok = withContext(Dispatchers.Default) { VaultActions.addDuress(pw.toCharArray(), action, label) }
                    busy = false
                    if (ok) {
                        ctx.toast("Duress password added"); onDone()
                    } else error = "No free slots left (maximum 3 duress passwords)"
                }
            }) { Text("Add") }
        },
        dismissButton = { TextButton(enabled = !busy, onClick = onDone) { Text("Cancel") } },
    )
}

@Composable
private fun CalculatorCodeDialog(onDismiss: () -> Unit, onSet: (String) -> Unit) {
    var code by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Calculator code") },
        text = {
            Column {
                Text("Digits only, 4–12 long. Type it into the calculator and press = to open Enclave.", style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(
                    code, { v -> code = v.filter { it.isDigit() }.take(12) }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
        },
        confirmButton = { TextButton(enabled = code.length >= 4, onClick = { onSet(code) }) { Text("Save") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun CustomShortcut() {
    val ctx = LocalContext.current
    var name by remember { mutableStateOf("") }
    var icon by remember { mutableStateOf<Bitmap?>(null) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri: Uri? ->
        if (uri != null) icon = runCatching { adaptiveIcon(ctx.contentResolver.openInputStream(uri)!!.use { BitmapFactory.decodeStream(it) }) }.getOrNull()
    }
    Column(Modifier.padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Custom home-screen icon", style = MaterialTheme.typography.titleSmall)
        Text(
            "Any name and any picture. It's added as a home-screen shortcut (your launcher will ask to confirm); the app drawer keeps the disguise chosen above.",
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Box(Modifier.size(56.dp).clip(CircleShape).clickable {
                leavingOnPurpose(); pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
            }) {
                Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxSize()) {}
                icon?.let { Image(it.asImageBitmap(), null, Modifier.fillMaxSize()) }
                    ?: Text("Pick", Modifier.align(Alignment.Center), style = MaterialTheme.typography.labelSmall)
            }
            OutlinedTextField(name, { name = it.take(24) }, label = { Text("Name") }, singleLine = true, modifier = Modifier.weight(1f))
        }
        OutlinedButton(enabled = name.isNotBlank() && icon != null, onClick = {
            if (!Disguise.canPinShortcut(ctx)) ctx.toast("Your launcher doesn't support custom shortcuts")
            else if (!Disguise.pinCustom(ctx, name.trim(), icon!!)) ctx.toast("The launcher refused the shortcut")
        }) { Text("Add to home screen") }
    }
}

/** Centre-crops the picture into a 432 px square sized for an adaptive icon's safe zone. */
private fun adaptiveIcon(src: Bitmap): Bitmap {
    val size = 432
    val out = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888)
    val side = minOf(src.width, src.height)
    val crop = Rect((src.width - side) / 2, (src.height - side) / 2, (src.width + side) / 2, (src.height + side) / 2)
    Canvas(out).drawBitmap(src, crop, Rect(0, 0, size, size), null)
    return out
}

@Composable
private fun WipeDialog(onDismiss: () -> Unit) {
    var typed by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Wipe everything?") },
        text = {
            Column {
                Text("Destroys the hardware key, every password and every file. There is no way back. Type WIPE to confirm.")
                OutlinedTextField(typed, { typed = it }, singleLine = true, modifier = Modifier.padding(top = 8.dp))
            }
        },
        confirmButton = {
            TextButton(enabled = typed == "WIPE", onClick = { VaultActions.wipeEverything() }) {
                Text("Wipe", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Default apps, viewer behaviour, and whether other apps may pick files from Enclave. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun OpeningSettings(s: Session.Unlocked) {
    val ctx = LocalContext.current
    val settings by s.store.settings.collectAsStateWithLifecycle()
    var choosing by remember { mutableStateOf<Triple<String, String, String>?>(null) } // key, title, mime
    var pickOn by remember { mutableStateOf(PickActivity.isEnabled(ctx)) }

    fun label(v: String) = when (v) {
        Opener.IN_ENCLAVE -> "Play in Enclave"
        Opener.ASK -> "Ask every time"
        else -> Opener.appLabel(ctx, v) ?: "Ask every time"
    }

    SectionTitle("Opening files")
    ListItem(
        modifier = Modifier.clickable { choosing = Triple("videos", "Open videos with", "video/*") },
        headlineContent = { Text("Videos") }, supportingContent = { Text(label(settings.openVideos)) },
    )
    ListItem(
        modifier = Modifier.clickable { choosing = Triple("audio", "Open music & audio with", "audio/*") },
        headlineContent = { Text("Music & audio") }, supportingContent = { Text(label(settings.openAudio)) },
    )
    ListItem(
        modifier = Modifier.clickable { choosing = Triple("other", "Open PDFs & other files with", "application/pdf") },
        headlineContent = { Text("PDFs & other files") }, supportingContent = { Text(label(settings.openOther)) },
    )
    Text(
        "Photos, GIFs and text always open in Enclave. Any file can still go to another app with “Open with another app”.",
        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    SectionTitle("Viewer")
    Text("Swipe between files", style = MaterialTheme.typography.bodyMedium)
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = !settings.swipeVertical, onClick = { s.store.updateSettings { it.copy(swipeVertical = false) } }, label = { Text("Left / right") })
        FilterChip(selected = settings.swipeVertical, onClick = { s.store.updateSettings { it.copy(swipeVertical = true) } }, label = { Text("Up / down") })
    }
    Text("Slideshow speed", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 8.dp))
    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        listOf(2, 4, 8, 15).forEach { sec ->
            FilterChip(
                selected = settings.slideshowSeconds == sec,
                onClick = { s.store.updateSettings { it.copy(slideshowSeconds = sec) } },
                label = { Text("$sec s") },
            )
        }
    }

    SectionTitle("Sharing")
    var editingShare by remember { mutableStateOf(false) }
    ListItem(
        modifier = Modifier.clickable { editingShare = true },
        headlineContent = { Text("Apps you can share to") },
        supportingContent = {
            Text(
                if (settings.shareApps.isEmpty()) "All apps (people and chats never appear). Tap to choose only a few."
                else "${settings.shareApps.size} app(s) chosen. Tap to change.",
            )
        },
    )
    ListItem(
        headlineContent = { Text("Confirm before sending") },
        supportingContent = { Text("Shows the files and the app, and asks before anything leaves Enclave.") },
        trailingContent = {
            Switch(checked = settings.confirmShare, onCheckedChange = { on -> s.store.updateSettings { it.copy(confirmShare = on) } })
        },
    )
    if (editingShare) {
        val targets = remember { Opener.allShareTargets(ctx) }
        ShareAppsEditor(s.store, targets, onDone = { editingShare = false })
    }

    SectionTitle("Other apps")
    ListItem(
        headlineContent = { Text("Let apps pick files from Enclave") },
        supportingContent = {
            Text(
                "Enclave appears when a browser, forum or chat asks you to choose a file. You unlock first, and the app only gets the " +
                    "files you tap. Note: it shows up there with the name “Enclave”, even when disguised.",
            )
        },
        trailingContent = {
            Switch(checked = pickOn, onCheckedChange = { on -> PickActivity.setEnabled(ctx, on); pickOn = on })
        },
    )

    choosing?.let { (key, title, mime) ->
        val apps = remember(mime) { Opener.appsFor(ctx, mime) }
        val current = when (key) { "videos" -> settings.openVideos; "audio" -> settings.openAudio; else -> settings.openOther }
        val options = buildList {
            if (key != "other") add(Opener.IN_ENCLAVE to "Play in Enclave (most private)")
            add(Opener.ASK to "Ask every time")
            apps.forEach { add(it) }
        }
        AlertDialog(
            onDismissRequest = { choosing = null },
            title = { Text(title) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    options.forEach { (v, l) ->
                        Row(
                            Modifier.fillMaxWidth().selectable(selected = current == v, onClick = {
                                s.store.updateSettings {
                                    when (key) {
                                        "videos" -> it.copy(openVideos = v)
                                        "audio" -> it.copy(openAudio = v)
                                        else -> it.copy(openOther = v)
                                    }
                                }
                                choosing = null
                            }),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(selected = current == v, onClick = null)
                            Text(l, Modifier.padding(start = 8.dp))
                        }
                    }
                    if (apps.isEmpty()) Text("No other apps here can open these.", style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = { TextButton(onClick = { choosing = null }) { Text("Cancel") } },
        )
    }
}
