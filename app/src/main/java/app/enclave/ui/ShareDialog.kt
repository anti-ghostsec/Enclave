package app.enclave.ui

import android.content.pm.ResolveInfo
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.vault.Entry
import app.enclave.vault.VaultStore

private const val SECURE_FOLDER = "com.motorola.securevault"

/** Shows the share prompt whenever something asks to share. Place once per screen. */
@Composable
fun ShareHost(store: VaultStore) {
    val files by Opener.pendingShare.collectAsStateWithLifecycle()
    files?.let { ShareDialog(store, it, onDone = { Opener.pendingShare.value = null }) }
}

/**
 * Enclave's own share list. Unlike Android's share sheet it never shows people or recent chats,
 * only apps, and only the apps you allowed in Settings. You then choose the person inside that
 * app. An optional confirmation step shows exactly what goes where.
 */
@Composable
private fun ShareDialog(store: VaultStore, files: List<Entry>, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val settings by store.settings.collectAsStateWithLifecycle()
    val all = remember(files) { Opener.shareTargets(ctx, files) }
    val allowed = settings.shareApps
    // Motorola Secure Folder's share entry is the way out to the normal side of the phone
    // (e.g. its Downloads folder). It isn't a person, so it's always offered, at the top.
    val outside = all.filter { it.activityInfo.packageName == SECURE_FOLDER }
    val apps = all - outside.toSet()
    val shown = outside + if (allowed.isEmpty()) apps else apps.filter { Opener.componentOf(it).flattenToString() in allowed }
    var confirming by remember { mutableStateOf<ResolveInfo?>(null) }
    var editing by remember { mutableStateOf(false) }
    val pm = ctx.packageManager

    if (editing) {
        ShareAppsEditor(store, all, onDone = { editing = false })
        return
    }

    val target = confirming
    if (target != null) {
        val app = target.loadLabel(pm).toString()
        AlertDialog(
            onDismissRequest = { confirming = null },
            title = { Text("Send to $app?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("${files.size} file(s):", fontWeight = FontWeight.SemiBold)
                    files.take(6).forEach { Text("• ${it.name}", style = MaterialTheme.typography.bodySmall) }
                    if (files.size > 6) Text("…and ${files.size - 6} more", style = MaterialTheme.typography.bodySmall)
                    Text(
                        "$app opens next. Check who you're sending to there before you tap send.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
            },
            confirmButton = {
                Button(onClick = { Opener.sendTo(ctx, store, files, Opener.componentOf(target)); onDone() }) { Text("Open $app") }
            },
            dismissButton = { TextButton(onClick = { confirming = null }) { Text("Back") } },
        )
        return
    }

    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(if (files.size == 1) "Share “${files[0].name}” with…" else "Share ${files.size} files with…") },
        text = {
            Column {
                if (shown.isEmpty()) {
                    Text(
                        if (all.isEmpty()) "No app here can receive these files." else "None of your chosen share apps can receive these files.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                LazyColumn(Modifier.heightIn(max = 380.dp)) {
                    items(shown, key = { Opener.componentOf(it).flattenToString() }) { r ->
                        ListItem(
                            modifier = Modifier.clickable {
                                if (settings.confirmShare) confirming = r
                                else { Opener.sendTo(ctx, store, files, Opener.componentOf(r)); onDone() }
                            },
                            headlineContent = {
                                Text(if (r in outside) "Outside Secure Folder" else r.loadLabel(pm).toString())
                            },
                            supportingContent = {
                                if (r in outside) Text("To the normal side of your phone, e.g. Downloads (Motorola Secure Folder)")
                            },
                            leadingContent = { AppIcon(r) },
                        )
                    }
                }
                TextButton(onClick = { editing = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(if (allowed.isEmpty()) "Limit this list to apps you choose" else "Change which apps appear here")
                }
            }
        },
        confirmButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}

@Composable
private fun AppIcon(r: ResolveInfo) {
    val ctx = LocalContext.current
    val icon = remember(r) { runCatching { r.loadIcon(ctx.packageManager).toBitmap(96, 96).asImageBitmap() }.getOrNull() }
    if (icon != null) Image(icon, null, Modifier.size(36.dp))
}

/** Pick the apps that may appear when sharing. Saved inside the encrypted vault. */
@Composable
fun ShareAppsEditor(store: VaultStore, targets: List<ResolveInfo>, onDone: () -> Unit) {
    val ctx = LocalContext.current
    val pm = ctx.packageManager
    val chosen = remember { mutableStateListOf<String>().apply { addAll(store.settings.value.shareApps) } }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text("Apps you can share to") },
        text = {
            Column {
                Text(
                    "Only ticked apps will appear when you share. Leave all unticked to show every app (people and chats never appear either way).",
                    style = MaterialTheme.typography.bodySmall,
                )
                LazyColumn(Modifier.heightIn(max = 400.dp).padding(top = 8.dp)) {
                    items(targets, key = { Opener.componentOf(it).flattenToString() }) { r ->
                        val id = Opener.componentOf(r).flattenToString()
                        ListItem(
                            modifier = Modifier.clickable { if (id in chosen) chosen.remove(id) else chosen.add(id) },
                            headlineContent = { Text(r.loadLabel(pm).toString()) },
                            leadingContent = { AppIcon(r) },
                            trailingContent = { Checkbox(checked = id in chosen, onCheckedChange = null) },
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { store.updateSettings { it.copy(shareApps = chosen.toList()) }; onDone() }) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDone) { Text("Cancel") } },
    )
}
