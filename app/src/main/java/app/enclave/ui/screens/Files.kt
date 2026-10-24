package app.enclave.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.automirrored.filled.Sort
import androidx.compose.material.icons.automirrored.filled.ViewList
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.MusicNote
import androidx.compose.material.icons.filled.PictureAsPdf
import androidx.compose.material.icons.filled.PlayCircle
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.HorizontalDivider
import androidx.compose.runtime.produceState
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import app.enclave.vault.Media
import kotlinx.coroutines.ExperimentalCoroutinesApi
import java.text.DateFormat
import java.util.Date
import android.graphics.Bitmap
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.PickVisualMediaRequest
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material.icons.automirrored.filled.DriveFileMove
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.SelectAll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.items as gridItems
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CreateNewFolder
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Image
import androidx.compose.material.icons.filled.Movie
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.enclave.ui.BrowseMode
import app.enclave.ui.Opener
import app.enclave.ui.StorageBrowser
import app.enclave.ui.freeName
import androidx.compose.material.icons.filled.Share
import java.io.File
import app.enclave.ui.leavingOnPurpose
import app.enclave.ui.openExternally
import app.enclave.ui.toast
import app.enclave.vault.DecryptedFileProvider
import app.enclave.vault.Entry
import app.enclave.vault.VaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Set when another app asked to pick a file from Enclave (e.g. a website's upload button). */
class PickRequest(val allowMultiple: Boolean, val onPick: (List<Entry>) -> Unit)

@OptIn(ExperimentalFoundationApi::class, ExperimentalMaterial3Api::class)
@Composable
fun FilesScreen(store: VaultStore, onView: (List<Entry>, Int) -> Unit, pick: PickRequest? = null) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val all by store.entries.collectAsStateWithLifecycle()
    val path = remember { mutableStateListOf<Entry>() }
    val folder = path.lastOrNull()
    val settings by store.settings.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }
    val searching = query.isNotBlank()
    // Searching looks through the whole vault, not just the open folder.
    val children = remember(all, folder, query, settings.sort, settings.sortDescending) {
        val base = if (searching) all.filter { it.name.contains(query.trim(), ignoreCase = true) } else store.children(folder?.id)
        sortEntries(base, settings.sort, settings.sortDescending)
    }
    var sortMenu by remember { mutableStateOf(false) }
    val selected = remember { mutableStateListOf<String>() }
    val selecting = selected.isNotEmpty()

    var importing by remember { mutableStateOf<Pair<Int, Int>?>(null) }
    var deleteOriginals by remember { mutableStateOf<List<File>>(emptyList()) }
    var browseImport by remember { mutableStateOf(false) }
    var newFolder by remember { mutableStateOf(false) }
    var renaming by remember { mutableStateOf<Entry?>(null) }
    var deleting by remember { mutableStateOf<List<String>>(emptyList()) }
    var moving by remember { mutableStateOf<List<String>>(emptyList()) }
    var exporting by remember { mutableStateOf<List<String>>(emptyList()) }
    var addMenu by remember { mutableStateOf(false) }

    // Back clears the selection first, then goes up a folder.
    BackHandler(enabled = selecting || searching || path.isNotEmpty()) {
        when {
            selecting -> selected.clear()
            searching -> query = ""
            else -> path.removeAt(path.lastIndex)
        }
    }
    LaunchedEffect(all) { selected.retainAll(all.map { it.id }.toSet()) }

    fun importAll(sources: List<Any>) {
        if (sources.isEmpty()) return
        scope.launch {
            val doneFiles = mutableListOf<File>()
            var done = 0
            sources.forEachIndexed { i, src ->
                importing = i to sources.size
                withContext(Dispatchers.IO) {
                    runCatching {
                        if (src is File) store.importFile(src, folder?.id) else store.import(ctx.contentResolver, src as Uri, folder?.id)
                    }
                }.onSuccess { done++; if (src is File) doneFiles += src }
                    .onFailure { ctx.toast("Couldn't import a file: ${it.message}") }
            }
            importing = null
            if (doneFiles.isNotEmpty()) deleteOriginals = doneFiles
            else if (done > 0) ctx.toast("$done encrypted. Delete the originals from your Gallery app.")
        }
    }

    val mediaImporter = rememberLauncherForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(100)) { importAll(it) }

    fun toggle(e: Entry) {
        if (e.id in selected) selected.remove(e.id) else selected.add(e.id)
    }

    fun open(e: Entry) {
        when {
            selecting -> toggle(e)
            searching && e.folder -> {
                query = ""; path.clear()
                path.addAll(ancestors(all, e)); path += e
            }
            e.folder -> path += e
            pick != null -> pick.onPick(listOf(e))
            Opener.preferenceFor(settings, e) == Opener.IN_ENCLAVE && Media.isViewable(e) -> {
                // Swipe through everything in this folder (or these results) that opens in Enclave.
                val list = children.filter { !it.folder && Media.isViewable(it) && Opener.preferenceFor(settings, it) == Opener.IN_ENCLAVE }
                onView(list, list.indexOf(e))
            }
            else -> Opener.openExternally(ctx, store, e)
        }
    }

    fun startExport(ids: List<String>) {
        exporting = ids
    }

    fun share(ids: Collection<String>) = Opener.share(ctx, store, all.filter { it.id in ids })

    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            if (selecting) {
                TopAppBar(
                    title = { Text("${selected.size} selected") },
                    navigationIcon = { IconButton(onClick = { selected.clear() }) { Icon(Icons.Default.Close, "Cancel") } },
                    actions = {
                        IconButton(onClick = {
                            if (selected.size == children.size) selected.clear()
                            else { selected.clear(); selected.addAll(children.map { it.id }) }
                        }) { Icon(Icons.Default.SelectAll, "Select all") }
                        if (pick != null) {
                            TextButton(onClick = { pick.onPick(all.filter { it.id in selected && !it.folder }) }) { Text("Send (${selected.size})") }
                        } else {
                            IconButton(onClick = { share(selected) }) { Icon(Icons.Default.Share, "Share") }
                            IconButton(onClick = { moving = selected.toList() }) { Icon(Icons.AutoMirrored.Filled.DriveFileMove, "Move") }
                            IconButton(onClick = { startExport(selected.toList()) }) { Icon(Icons.Default.Download, "Export") }
                            IconButton(onClick = { deleting = selected.toList() }) { Icon(Icons.Default.Delete, "Delete") }
                        }
                    },
                )
            } else {
                Row(
                    Modifier.fillMaxWidth().padding(start = 12.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedTextField(
                        query, { query = it },
                        placeholder = { Text("Search all files") },
                        singleLine = true,
                        leadingIcon = { Icon(Icons.Default.Search, null) },
                        trailingIcon = if (searching) {
                            { IconButton(onClick = { query = "" }) { Icon(Icons.Default.Close, "Clear") } }
                        } else null,
                        modifier = Modifier.weight(1f),
                    )
                    Box {
                        IconButton(onClick = { sortMenu = true }) { Icon(Icons.AutoMirrored.Filled.Sort, "Sort") }
                        DropdownMenu(expanded = sortMenu, onDismissRequest = { sortMenu = false }) {
                            listOf("name" to "Name", "date" to "Date added", "size" to "Size", "type" to "Type").forEach { (k, label) ->
                                DropdownMenuItem(
                                    text = { Text(label) },
                                    leadingIcon = { if (settings.sort == k) Icon(Icons.Default.Check, null) },
                                    onClick = { sortMenu = false; store.updateSettings { it.copy(sort = k) } },
                                )
                            }
                            HorizontalDivider()
                            DropdownMenuItem(
                                text = { Text(if (settings.sortDescending) "Descending" else "Ascending") },
                                leadingIcon = { Icon(if (settings.sortDescending) Icons.Default.ArrowDownward else Icons.Default.ArrowUpward, null) },
                                onClick = { sortMenu = false; store.updateSettings { it.copy(sortDescending = !it.sortDescending) } },
                            )
                        }
                    }
                    IconButton(onClick = { store.updateSettings { it.copy(grid = !it.grid) } }) {
                        Icon(if (settings.grid) Icons.AutoMirrored.Filled.ViewList else Icons.Default.GridView, "Change view")
                    }
                }
                if (searching) {
                    Text(
                        "${children.size} result(s) in the whole vault",
                        style = MaterialTheme.typography.labelMedium,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    )
                } else if (path.isNotEmpty()) {
                    ListItem(
                        headlineContent = { Text(path.joinToString(" / ") { it.name }) },
                        leadingContent = {
                            IconButton(onClick = { path.removeAt(path.lastIndex) }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Up") }
                        },
                    )
                }
            }
            val upgrading by store.upgrade.collectAsStateWithLifecycle()
            upgrading?.let { (i, n) ->
                Text("Adding size padding to older files: $i of $n (keep Enclave open)", Modifier.padding(horizontal = 16.dp), style = MaterialTheme.typography.labelMedium)
                LinearProgressIndicator(progress = { if (n > 0) i.toFloat() / n else 0f }, modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp))
            }
            importing?.let { (i, n) ->
                Text("Encrypting ${i + 1} of $n…", Modifier.padding(horizontal = 16.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(16.dp))
            }
            if (children.isEmpty() && importing == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (searching) "No files match “${query.trim()}”."
                        else "Nothing here yet.\nTap Add to encrypt files into the vault.\nLong-press a file to select several.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center,
                    )
                }
            }

            @Composable
            fun ItemMenu(e: Entry, expanded: Boolean, onClose: () -> Unit) {
                DropdownMenu(expanded = expanded, onDismissRequest = onClose) {
                    if (!e.folder) {
                        DropdownMenuItem(text = { Text("Share") }, onClick = { onClose(); share(listOf(e.id)) })
                        DropdownMenuItem(text = { Text("Open with another app") }, onClick = { onClose(); Opener.openExternally(ctx, store, e, alwaysAsk = true) })
                    }
                    DropdownMenuItem(text = { Text("Select") }, onClick = { onClose(); toggle(e) })
                    DropdownMenuItem(text = { Text("Move to folder") }, onClick = { onClose(); moving = listOf(e.id) })
                    DropdownMenuItem(text = { Text("Export decrypted copy") }, onClick = { onClose(); startExport(listOf(e.id)) })
                    DropdownMenuItem(text = { Text("Rename") }, onClick = { onClose(); renaming = e })
                    DropdownMenuItem(text = { Text("Delete") }, onClick = { onClose(); deleting = listOf(e.id) })
                }
            }

            if (settings.grid) {
                LazyVerticalGrid(
                    GridCells.Adaptive(112.dp), Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(start = 8.dp, end = 8.dp, bottom = 88.dp),
                ) {
                    gridItems(children, key = { it.id }) { e ->
                        var menu by remember { mutableStateOf(false) }
                        val isSel = e.id in selected
                        Column(
                            Modifier.padding(4.dp).clip(RoundedCornerShape(10.dp))
                                .combinedClickable(onClick = { open(e) }, onLongClick = { if (pick == null || pick.allowMultiple) toggle(e) })
                                .background(if (isSel) MaterialTheme.colorScheme.secondaryContainer else Color.Transparent)
                                .padding(4.dp),
                        ) {
                            Box(Modifier.fillMaxWidth().aspectRatio(1f)) {
                                Preview(store, e, Modifier.fillMaxSize())
                                if (selecting) {
                                    Checkbox(checked = isSel, onCheckedChange = { toggle(e) }, modifier = Modifier.align(Alignment.TopStart))
                                } else if (pick == null) Box(Modifier.align(Alignment.TopEnd)) {
                                    IconButton(onClick = { menu = true }, modifier = Modifier.size(32.dp)) {
                                        Icon(Icons.Default.MoreVert, "More", tint = Color.White)
                                    }
                                    ItemMenu(e, menu) { menu = false }
                                }
                            }
                            Text(e.name, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 4.dp))
                        }
                    }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 88.dp)) {
                    items(children, key = { it.id }) { e ->
                        var menu by remember { mutableStateOf(false) }
                        val isSel = e.id in selected
                        ListItem(
                            modifier = Modifier.combinedClickable(onClick = { open(e) }, onLongClick = { if (pick == null || pick.allowMultiple) toggle(e) }),
                            colors = if (isSel) ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.secondaryContainer) else ListItemDefaults.colors(),
                            headlineContent = { Text(e.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            supportingContent = {
                                val detail = if (e.folder) "Folder" else "${humanSize(e.size)} · ${dateFormat.format(Date(e.added))}"
                                Text(if (searching) "${store.pathOf(e).substringBeforeLast(" / ", "Vault")} · $detail" else detail, maxLines = 1)
                            },
                            leadingContent = {
                                if (selecting) Checkbox(checked = isSel, onCheckedChange = { toggle(e) })
                                else Preview(store, e, Modifier.size(48.dp))
                            },
                            trailingContent = {
                                if (!selecting && pick == null) Box {
                                    IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, "More") }
                                    ItemMenu(e, menu) { menu = false }
                                }
                            },
                        )
                    }
                }
            }
        }
        if (!selecting && pick == null) Box(Modifier.align(Alignment.BottomEnd).padding(16.dp)) {
            ExtendedFloatingActionButton(
                onClick = { addMenu = true },
                icon = { Icon(Icons.Default.Add, null) }, text = { Text("Add") },
            )
            DropdownMenu(expanded = addMenu, onDismissRequest = { addMenu = false }) {
                DropdownMenuItem(
                    text = { Text("Photos & videos") }, leadingIcon = { Icon(Icons.Default.PhotoLibrary, null) },
                    onClick = {
                        addMenu = false; leavingOnPurpose()
                        mediaImporter.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo))
                    },
                )
                DropdownMenuItem(
                    text = { Text("Files from storage") }, leadingIcon = { Icon(Icons.Default.UploadFile, null) },
                    onClick = { addMenu = false; browseImport = true },
                )
                DropdownMenuItem(
                    text = { Text("New folder") }, leadingIcon = { Icon(Icons.Default.CreateNewFolder, null) },
                    onClick = { addMenu = false; newFolder = true },
                )
            }
        }
    }

    if (newFolder) NameDialog("New folder", "", onDismiss = { newFolder = false }) {
        store.createFolder(it, folder?.id); newFolder = false
    }
    renaming?.let { e ->
        NameDialog("Rename", e.name, onDismiss = { renaming = null }) { store.rename(e, it); renaming = null }
    }
    if (moving.isNotEmpty()) {
        MoveDialog(store, all, moving, onDismiss = { moving = emptyList() }) { target ->
            store.move(moving, target)
            ctx.toast("Moved ${moving.size} item(s)")
            moving = emptyList(); selected.clear()
        }
    }
    if (deleting.isNotEmpty()) {
        val one = if (deleting.size == 1) all.firstOrNull { it.id == deleting[0] } else null
        AlertDialog(
            onDismissRequest = { deleting = emptyList() },
            title = { Text(if (one != null) "Delete “${one.name}”?" else "Delete ${deleting.size} items?") },
            text = { Text("Folders are deleted with everything in them. This can't be undone.") },
            confirmButton = {
                TextButton(onClick = { store.delete(deleting); deleting = emptyList(); selected.clear() }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { deleting = emptyList() }) { Text("Cancel") } },
        )
    }
    if (browseImport) {
        StorageBrowser(BrowseMode.FILES, onDismiss = { browseImport = false }, confirmLabel = "Encrypt into vault") { files ->
            browseImport = false
            importAll(files)
        }
    }
    if (exporting.isNotEmpty()) {
        StorageBrowser(BrowseMode.FOLDER, onDismiss = { exporting = emptyList() }, confirmLabel = "Export here") { dirs ->
            val ids = exporting
            exporting = emptyList()
            scope.launch {
                val n = withContext(Dispatchers.IO) { runCatching { store.exportTo(ids, dirs[0], ::freeName) }.getOrDefault(-1) }
                if (n < 0) ctx.toast("Export failed") else ctx.toast("Exported $n decrypted file(s) to ${dirs[0].name}")
                selected.clear()
            }
        }
    }
    if (deleteOriginals.isNotEmpty()) {
        AlertDialog(
            onDismissRequest = { deleteOriginals = emptyList() },
            title = { Text("Delete the originals?") },
            text = {
                Text(
                    "${deleteOriginals.size} file(s) are now encrypted in the vault. The unencrypted originals are still on the phone. " +
                        "Delete them? (Flash storage can't promise a secure erase, but this removes them from the gallery and file managers.)",
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    var failed = 0
                    deleteOriginals.forEach { if (!it.delete()) failed++ }
                    if (failed > 0) ctx.toast("$failed original(s) couldn't be deleted — remove them manually")
                    deleteOriginals = emptyList()
                }) { Text("Delete originals") }
            },
            dismissButton = { TextButton(onClick = { deleteOriginals = emptyList() }) { Text("Keep") } },
        )
    }
}

@Composable
private fun MoveDialog(store: VaultStore, all: List<Entry>, ids: List<String>, onDismiss: () -> Unit, onMove: (String?) -> Unit) {
    // Every folder that isn't one of the moved folders or inside one of them.
    val targets = remember(all, ids) {
        all.filter { f -> f.folder && ids.none { store.isWithin(f.id, it) } }
            .map { it to store.pathOf(it) }
            .sortedBy { it.second.lowercase() }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Move ${ids.size} item(s) to…") },
        text = {
            LazyColumn(Modifier.heightIn(max = 420.dp)) {
                item {
                    ListItem(
                        modifier = Modifier.clickable { onMove(null) },
                        headlineContent = { Text("Vault (top level)") },
                        leadingContent = { Icon(Icons.Default.Home, null) },
                    )
                }
                items(targets, key = { it.first.id }) { (f, label) ->
                    ListItem(
                        modifier = Modifier.clickable { onMove(f.id) },
                        headlineContent = { Text(label) },
                        leadingContent = { Icon(Icons.Default.Folder, null) },
                    )
                }
                if (targets.isEmpty()) item {
                    Text("Tip: create a folder first with Add → New folder.", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(16.dp))
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private val dateFormat: DateFormat = DateFormat.getDateInstance(DateFormat.MEDIUM)

@OptIn(ExperimentalCoroutinesApi::class)
private val thumbnailWork = Dispatchers.IO.limitedParallelism(3)

private fun iconFor(e: Entry) = when {
    e.folder -> Icons.Default.Folder
    Media.isImage(e) -> Icons.Default.Image
    Media.isVideo(e) -> Icons.Default.Movie
    e.mime.startsWith("audio/") -> Icons.Default.MusicNote
    e.mime == "application/pdf" -> Icons.Default.PictureAsPdf
    e.mime.startsWith("text/") -> Icons.Default.Description
    else -> Icons.AutoMirrored.Filled.InsertDriveFile
}

/** A decrypted-in-memory preview for photos and videos, or an icon for everything else. */
@Composable
private fun Preview(store: VaultStore, e: Entry, modifier: Modifier) {
    val thumb by produceState<Bitmap?>(null, e.id) {
        if (Media.isImage(e) || Media.isVideo(e)) value = withContext(thumbnailWork) { store.thumbnail(e) }
    }
    Box(
        modifier.clip(RoundedCornerShape(8.dp)).background(MaterialTheme.colorScheme.surfaceVariant),
        contentAlignment = Alignment.Center,
    ) {
        val t = thumb
        if (t != null) Image(t.asImageBitmap(), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
        else Icon(
            iconFor(e), null, Modifier.fillMaxSize(0.45f),
            tint = if (e.folder) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (Media.isVideo(e) && t != null) {
            Icon(Icons.Default.PlayCircle, null, Modifier.fillMaxSize(0.35f), tint = Color.White.copy(alpha = 0.9f))
        }
    }
}

private fun ancestors(all: List<Entry>, e: Entry): List<Entry> {
    val out = mutableListOf<Entry>()
    var cur = e.parent
    while (cur != null) {
        val p = all.firstOrNull { it.id == cur } ?: break
        out.add(0, p); cur = p.parent
    }
    return out
}

private fun sortEntries(list: List<Entry>, by: String, descending: Boolean): List<Entry> {
    val order: Comparator<Entry> = when (by) {
        "date" -> compareBy { it.added }
        "size" -> compareBy { it.size }
        "type" -> compareBy<Entry> { it.mime }.thenBy { it.name.lowercase() }
        else -> compareBy { it.name.lowercase() }
    }
    // Folders always come first.
    return list.sortedWith(compareBy<Entry> { !it.folder }.then(if (descending) order.reversed() else order))
}

@Composable
private fun NameDialog(title: String, initial: String, onDismiss: () -> Unit, onOk: (String) -> Unit) {
    var name by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { OutlinedTextField(name, { name = it }, singleLine = true) },
        confirmButton = { TextButton(enabled = name.isNotBlank(), onClick = { onOk(name.trim()) }) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

fun humanSize(b: Long): String = when {
    b < 1024 -> "$b B"
    b < 1024 * 1024 -> "%.1f KB".format(b / 1024.0)
    b < 1024L * 1024 * 1024 -> "%.1f MB".format(b / 1048576.0)
    else -> "%.2f GB".format(b / 1073741824.0)
}
