package app.enclave.ui

import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Environment
import android.util.LruCache
import android.provider.Settings
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.LifecycleResumeEffect
import app.enclave.ui.screens.humanSize
import app.enclave.vault.Media
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.withContext
import java.io.File

enum class BrowseMode { FILE, FILES, FOLDER }

/**
 * A folder browser inside Enclave. Android's own file picker only shows "Recent" inside
 * Motorola's Secure Folder, so Enclave reads storage directly instead. That needs Android's
 * "All files access", which is requested the first time.
 *
 * FILE picks one file, FILES picks several, FOLDER picks a destination ("Save here").
 */
@Composable
fun StorageBrowser(
    mode: BrowseMode,
    onDismiss: () -> Unit,
    confirmLabel: String = "Save here",
    onPick: (List<File>) -> Unit,
) {
    val ctx = LocalContext.current
    val root = remember { Environment.getExternalStorageDirectory() }
    var dir by remember { mutableStateOf(root) }
    var granted by remember { mutableStateOf(Environment.isExternalStorageManager()) }
    val chosen = remember { mutableStateListOf<File>() }
    var refresh by remember { mutableIntStateOf(0) }
    var newFolder by remember { mutableStateOf(false) }
    // Previews live only in memory, and only while the browser is open.
    val thumbs = remember {
        object : LruCache<String, Bitmap>(16 * 1024 * 1024) {
            override fun sizeOf(key: String, value: Bitmap) = value.byteCount
        }
    }
    DisposableEffect(Unit) { onDispose { thumbs.evictAll() } }
    LifecycleResumeEffect(Unit) {
        granted = Environment.isExternalStorageManager()
        onPauseOrDispose { }
    }

    fun up() {
        if (dir == root) onDismiss() else dir = dir.parentFile ?: root
    }

    Dialog(onDismissRequest = ::up, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.systemBarsPadding()) {
                Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = ::up) {
                        Icon(if (dir == root) Icons.Default.Close else Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                    Text(
                        if (dir == root) "Phone storage" else dir.relativeTo(root).path,
                        style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.StartEllipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (granted && mode == BrowseMode.FOLDER) {
                        IconButton(onClick = { newFolder = true }) { Icon(Icons.Default.CreateNewFolder, "New folder") }
                    }
                }
                if (!granted) {
                    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("To browse folders here, Enclave needs “All files access”.")
                        Text(
                            "Enclave has no internet permission, so it can't send anything anywhere. It only reads or writes the files you choose. " +
                                "You can turn this off again any time in Android Settings.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(onClick = {
                            leavingOnPurpose()
                            val perApp = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:${ctx.packageName}"))
                            runCatching { ctx.startActivity(perApp) }
                                .onFailure { runCatching { ctx.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) } }
                        }) { Text("Allow access") }
                    }
                } else {
                    val items = remember(dir, refresh) {
                        (dir.listFiles() ?: emptyArray())
                            .filter { mode != BrowseMode.FOLDER || it.isDirectory }
                            .sortedWith(compareBy<File>({ !it.isDirectory }, { it.name.lowercase() }))
                    }
                    if (items.isEmpty()) Text(if (mode == BrowseMode.FOLDER) "No folders inside." else "This folder is empty.", Modifier.padding(24.dp))
                    LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
                        items(items, key = { it.path }) { f ->
                            ListItem(
                                modifier = Modifier.clickable {
                                    when {
                                        f.isDirectory -> dir = f
                                        mode == BrowseMode.FILES -> if (f in chosen) chosen.remove(f) else chosen.add(f)
                                        else -> onPick(listOf(f))
                                    }
                                },
                                headlineContent = { Text(f.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                supportingContent = { if (!f.isDirectory) Text(humanSize(f.length())) },
                                leadingContent = { BrowsePreview(f, thumbs) },
                                trailingContent = {
                                    if (mode == BrowseMode.FILES && !f.isDirectory) Checkbox(checked = f in chosen, onCheckedChange = null)
                                },
                            )
                        }
                    }
                    when (mode) {
                        BrowseMode.FILES -> Button(
                            enabled = chosen.isNotEmpty(), onClick = { onPick(chosen.toList()) },
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                        ) { Text(if (chosen.isEmpty()) "Tap files to choose them" else "$confirmLabel (${chosen.size})") }
                        BrowseMode.FOLDER -> Button(
                            onClick = { onPick(listOf(dir)) }, modifier = Modifier.fillMaxWidth().padding(16.dp),
                        ) { Text(confirmLabel) }
                        BrowseMode.FILE -> Unit
                    }
                }
            }
        }
    }

    if (newFolder) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { newFolder = false },
            title = { Text("New folder") },
            text = { OutlinedTextField(name, { name = it }, singleLine = true) },
            confirmButton = {
                TextButton(enabled = name.isNotBlank(), onClick = {
                    val f = File(dir, name.trim())
                    if (f.mkdirs()) dir = f else ctx.toast("Couldn't create that folder")
                    newFolder = false; refresh++
                }) { Text("Create") }
            },
            dismissButton = { TextButton(onClick = { newFolder = false }) { Text("Cancel") } },
        )
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
private val browseThumbnailWork = Dispatchers.IO.limitedParallelism(3)

private fun browseIconFor(f: File): ImageVector {
    if (f.isDirectory) return Icons.Default.Folder
    val mime = Media.mimeOfName(f.name)
    return when {
        mime.startsWith("image/") -> Icons.Default.Image
        mime.startsWith("video/") -> Icons.Default.Movie
        mime.startsWith("audio/") -> Icons.Default.MusicNote
        mime == "application/pdf" -> Icons.Default.PictureAsPdf
        mime.startsWith("text/") -> Icons.Default.Description
        else -> Icons.AutoMirrored.Filled.InsertDriveFile
    }
}

/** A photo or video preview made in memory, or an icon for the file's type. */
@Composable
private fun BrowsePreview(f: File, thumbs: LruCache<String, Bitmap>) {
    val key = "${f.path}\u0000${f.lastModified()}"
    val thumb by produceState(thumbs.get(key), key) {
        if (value != null || f.isDirectory) return@produceState
        val mime = Media.mimeOfName(f.name)
        if (!mime.startsWith("image/") && !mime.startsWith("video/")) return@produceState
        value = withContext(browseThumbnailWork) { Media.makeThumbnail(f) }?.also { thumbs.put(key, it) }
    }
    Box(
        Modifier.size(48.dp).clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val t = thumb
        if (t != null) Image(t.asImageBitmap(), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
        else Icon(
            browseIconFor(f), null, Modifier.fillMaxSize(0.55f),
            tint = if (f.isDirectory) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (t != null && Media.mimeOfName(f.name).startsWith("video/")) {
            Icon(Icons.Default.PlayCircle, null, Modifier.fillMaxSize(0.45f), tint = Color.White.copy(alpha = 0.9f))
        }
    }
}

/**
 * A name that's safe as one file name: no folder separators, no "." or "..", no control
 * characters. Vault names can come from other apps, so they're never trusted as paths.
 */
fun safeFileName(name: String): String {
    val last = name.replace('\\', '/').substringAfterLast('/')
    val clean = last.filter { it >= ' ' && it != '\u007f' }.trim()
    return if (clean.isEmpty() || clean == "." || clean == "..") "file" else clean
}

/**
 * Picks a name like "photo (2).jpg" that doesn't exist yet in [dir]. The result is always
 * directly inside [dir].
 */
fun freeName(dir: File, rawName: String): File {
    val name = safeFileName(rawName)
    var f = File(dir, name)
    if (!f.exists()) return f
    val base = name.substringBeforeLast('.', name)
    val ext = if ('.' in name) "." + name.substringAfterLast('.') else ""
    var n = 1
    while (f.exists()) f = File(dir, "$base (${n++})$ext")
    return f
}
