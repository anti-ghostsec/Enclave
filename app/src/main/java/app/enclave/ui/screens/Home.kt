package app.enclave.ui.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import app.enclave.disguise.Disguise
import app.enclave.ui.ShareHost
import app.enclave.vault.Entry
import app.enclave.vault.Session

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(s: Session.Unlocked) {
    var tab by remember { mutableIntStateOf(0) }
    var viewing by remember { mutableStateOf<Pair<List<Entry>, Int>?>(null) }

    ShareHost(s.store)

    viewing?.let { (items, start) ->
        ViewerScreen(s.store, items, start, onClose = { viewing = null })
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(listOf("Files", "Settings")[tab]) },
                actions = {
                    IconButton(onClick = { Session.lock() }) { Icon(Icons.Default.Lock, "Lock now") }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                listOf(Icons.Default.Folder to "Files", Icons.Default.Settings to "Settings")
                    .forEachIndexed { i, (icon, label) ->
                        NavigationBarItem(
                            selected = tab == i, onClick = { tab = i },
                            icon = { Icon(icon, null) }, label = { Text(label) },
                        )
                    }
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad)) {
            when (tab) {
                0 -> FilesScreen(s.store, onView = { items, i -> viewing = items to i })
                else -> SettingsScreen(s, disguiseLabel = Disguise.current().label)
            }
        }
    }
}
