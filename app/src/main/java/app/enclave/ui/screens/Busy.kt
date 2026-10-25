package app.enclave.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.enclave.vault.Migration
import app.enclave.vault.Session

/** Shown while the vault is being moved into (or set up in) deniable storage. */
@Composable
fun BusyScreen(busy: Session.Busy) {
    val view = LocalView.current
    // The screen turning off locks the vault, which would pause the move.
    DisposableEffect(Unit) {
        view.keepScreenOn = true
        onDispose { view.keepScreenOn = false }
    }
    Box(Modifier.fillMaxSize().systemBarsPadding().padding(24.dp), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text(busy.title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
            val p = busy.progress
            if (p == null || p.total == 0L) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(
                    "Filling new storage with random bytes. This takes about a minute per 4 GB.",
                    style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center,
                )
            } else {
                LinearProgressIndicator(progress = { p.done.toFloat() / p.total }, modifier = Modifier.fillMaxWidth())
                Text(
                    (if (p.stage == Migration.Stage.Copying) "Copying" else "Checking every copy") +
                        " · ${humanSize(p.done)} of ${humanSize(p.total)}",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            Text(
                "Keep Enclave open. Your files stay where they are until every one has been copied and checked, " +
                    "so nothing is lost if this is interrupted: it carries on next time you unlock.",
                style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
