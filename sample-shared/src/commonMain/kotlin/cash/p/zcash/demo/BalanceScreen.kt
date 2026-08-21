package cash.p.zcash.demo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import cash.p.zcash.Pool
import cash.p.zcash.SyncState
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.action_cancel
import cash.p.zcash.demo.resources.action_refresh
import cash.p.zcash.demo.resources.action_reset
import cash.p.zcash.demo.resources.action_sync
import cash.p.zcash.demo.resources.balance_account
import cash.p.zcash.demo.resources.balance_chain_tip
import cash.p.zcash.demo.resources.balance_sync
import cash.p.zcash.demo.resources.balance_total
import cash.p.zcash.demo.resources.sync_connecting
import cash.p.zcash.demo.resources.sync_failed
import cash.p.zcash.demo.resources.sync_progress
import cash.p.zcash.demo.resources.sync_stopped
import cash.p.zcash.demo.resources.sync_synced
import org.jetbrains.compose.resources.stringResource

@Composable
internal fun BalanceScreen(
    uiState: DemoUiState,
    onSync: () -> Unit,
    onCancelSync: () -> Unit,
    onRefresh: () -> Unit,
    onReset: () -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(Res.string.balance_total), style = MaterialTheme.typography.labelMedium)
                Text(
                    text = zecAmount(uiState.balance?.total ?: 0L),
                    style = MaterialTheme.typography.headlineSmall,
                )
                Pool.entries.forEach { pool ->
                    LabeledRow(pool.name.lowercase(), zecAmount(uiState.balance?.get(pool)?.total ?: 0L))
                }
            }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(Res.string.balance_sync), style = MaterialTheme.typography.labelMedium)
                Text(uiState.syncState.describe(), style = MaterialTheme.typography.bodyLarge)
                val syncing = uiState.syncState
                if (syncing is SyncState.Syncing && syncing.target > 0) {
                    LinearProgressIndicator(
                        progress = { syncing.current.toFloat() / syncing.target.toFloat() },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                uiState.chainTip?.let { LabeledRow(stringResource(Res.string.balance_chain_tip), it.toString()) }
                uiState.accountId?.let { LabeledRow(stringResource(Res.string.balance_account), it.toString()) }
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = onSync, enabled = !uiState.syncing) {
                Text(stringResource(Res.string.action_sync))
            }
            OutlinedButton(onClick = onCancelSync, enabled = uiState.syncing) {
                Text(stringResource(Res.string.action_cancel))
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onRefresh) { Text(stringResource(Res.string.action_refresh)) }
            OutlinedButton(onClick = onReset, enabled = !uiState.syncing) {
                Text(stringResource(Res.string.action_reset))
            }
        }
    }
}

@Composable
private fun LabeledRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun SyncState.describe(): String = when (this) {
    SyncState.Stopped -> stringResource(Res.string.sync_stopped)
    SyncState.Connecting -> stringResource(Res.string.sync_connecting)
    is SyncState.Syncing -> stringResource(Res.string.sync_progress, current.toString(), target.toString())
    SyncState.Synced -> stringResource(Res.string.sync_synced)
    is SyncState.Failed -> stringResource(Res.string.sync_failed, error.message ?: error.toString())
}
