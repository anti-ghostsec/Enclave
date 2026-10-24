package app.enclave.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import app.enclave.vault.Entry
import app.enclave.vault.VaultStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

/**
 * Finds files with identical contents anywhere in the vault. Nothing is selected or deleted
 * until you choose; "Select extras" ticks every copy except the oldest in each group.
 */
@Composable
fun DuplicatesScreen(store: VaultStore, onClose: () -> Unit) {
    var progress by remember { mutableStateOf(0 to 0) }
    var groups by remember { mutableStateOf<List<List<Entry>>?>(null) }
    val selected = remember { mutableStateListOf<String>() }
    var confirm by remember { mutableStateOf(false) }
    val date = remember { DateFormat.getDateInstance(DateFormat.MEDIUM) }

    LaunchedEffect(Unit) {
        groups = withContext(Dispatchers.IO) { store.findDuplicates { d, t -> progress = d to t } }
    }

    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            Column(Modifier.systemBarsPadding()) {
                Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    IconButton(onClick = onClose) { Icon(Icons.Default.Close, "Close") }
                    Text("Duplicates", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                }
                val g = groups
                if (g == null) {
                    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Text("Comparing files… ${progress.first} of ${progress.second}")
                        LinearProgressIndicator(
                            progress = { if (progress.second > 0) progress.first.toFloat() / progress.second else 0f },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                    return@Column
                }
                if (g.isEmpty()) {
                    Text("No duplicates found. Every file in the vault is unique.", Modifier.padding(24.dp))
                    return@Column
                }
                val extraBytes = g.sumOf { it.first().size * (it.size - 1) }
                Text(
                    "${g.size} group(s) of identical files. Removing the extra copies would free ${humanSize(extraBytes)}.",
                    style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(horizontal = 16.dp),
                )
                Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = {
                        selected.clear(); g.forEach { grp -> selected.addAll(grp.drop(1).map { it.id }) }
                    }) { Text("Select extras") }
                    Button(enabled = selected.isNotEmpty(), onClick = { confirm = true }) { Text("Delete (${selected.size})") }
                }
                LazyColumn(Modifier.weight(1f)) {
                    items(g, key = { it.first().id }) { grp ->
                        Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp)) {
                            Text(
                                "${grp.size} copies · ${humanSize(grp.first().size)} each",
                                style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(start = 16.dp, top = 12.dp),
                            )
                            grp.forEachIndexed { i, e ->
                                ListItem(
                                    modifier = Modifier.clickable { if (e.id in selected) selected.remove(e.id) else selected.add(e.id) },
                                    headlineContent = { Text(e.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                    supportingContent = {
                                        val where = store.pathOf(e).substringBeforeLast(" / ", "Vault")
                                        Text("$where · added ${date.format(Date(e.added))}" + if (i == 0) " · oldest" else "", maxLines = 1)
                                    },
                                    leadingContent = { Preview(store, e, Modifier.size(48.dp)) },
                                    trailingContent = { Checkbox(checked = e.id in selected, onCheckedChange = null) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Delete ${selected.size} file(s)?") },
            text = { Text("They're removed from the vault for good. Unticked copies are kept.") },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    val gone = selected.toSet()
                    // Never delete every copy in a group, even if all were ticked.
                    val safe = groups.orEmpty().flatMap { grp ->
                        val ticked = grp.filter { it.id in gone }
                        if (ticked.size == grp.size) ticked.drop(1) else ticked
                    }.map { it.id }
                    store.delete(safe)
                    groups = groups?.map { grp -> grp.filter { it.id !in safe } }?.filter { it.size > 1 }
                    selected.clear()
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }
}
