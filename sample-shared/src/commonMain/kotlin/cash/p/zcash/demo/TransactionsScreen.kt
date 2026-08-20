package cash.p.zcash.demo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cash.p.zcash.Transaction
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.transaction_block
import cash.p.zcash.demo.resources.transaction_in_mempool
import cash.p.zcash.demo.resources.transactions_empty
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.number
import kotlinx.datetime.toLocalDateTime
import org.jetbrains.compose.resources.stringResource

private const val TXID_PREFIX = 12

@Composable
internal fun TransactionsScreen(transactions: List<Transaction>) {
    if (transactions.isEmpty()) {
        Text(
            text = stringResource(Res.string.transactions_empty),
            modifier = Modifier.padding(24.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize()) {
        items(transactions, key = Transaction::id) { transaction ->
            TransactionRow(transaction)
            HorizontalDivider()
        }
    }
}

@Composable
private fun TransactionRow(transaction: Transaction) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            val time = formatTimestamp(transaction.time) ?: stringResource(Res.string.transaction_in_mempool)
            val sign = if (transaction.value > 0) "+" else ""
            Text(time, style = MaterialTheme.typography.bodyMedium)
            Text(sign + zecAmount(transaction.value), style = MaterialTheme.typography.bodyMedium)
        }
        Text(
            text = stringResource(
                Res.string.transaction_block,
                transaction.height.toString(),
                transaction.txid.take(TXID_PREFIX),
            ),
            style = MaterialTheme.typography.bodySmall,
        )
        transaction.memo?.takeIf(String::isNotBlank)?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** Unconfirmed transactions carry no block time, and epoch zero is not a date worth showing. */
private fun formatTimestamp(epochSeconds: Long): String? {
    if (epochSeconds <= 0L) return null
    val time = Instant.fromEpochSeconds(epochSeconds).toLocalDateTime(TimeZone.currentSystemDefault())
    val month = time.month.number.toString().padStart(2, '0')
    val day = time.day.toString().padStart(2, '0')
    val hour = time.hour.toString().padStart(2, '0')
    val minute = time.minute.toString().padStart(2, '0')
    return "${time.year}-$month-$day $hour:$minute"
}
