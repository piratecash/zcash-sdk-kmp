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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.plan_amount
import cash.p.zcash.demo.resources.plan_fee
import cash.p.zcash.demo.resources.plan_height
import cash.p.zcash.demo.resources.plan_input
import cash.p.zcash.demo.resources.plan_output
import cash.p.zcash.demo.resources.plan_recipient
import cash.p.zcash.demo.resources.plan_title
import cash.p.zcash.demo.resources.send_address_label
import cash.p.zcash.demo.resources.send_amount_label
import cash.p.zcash.demo.resources.send_confirm
import cash.p.zcash.demo.resources.send_failed
import cash.p.zcash.demo.resources.send_retry
import cash.p.zcash.demo.resources.send_review
import cash.p.zcash.demo.resources.send_reviewing
import cash.p.zcash.demo.resources.send_sending
import cash.p.zcash.demo.resources.send_sent
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

@Composable
internal fun SendScreen(
    uiState: DemoUiState,
    onAddressChange: (String) -> Unit,
    onAmountChange: (String) -> Unit,
    onPrepare: () -> Unit,
    onConfirm: () -> Unit,
) {
    val busy = uiState.sendBusy
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = uiState.address,
            onValueChange = onAddressChange,
            enabled = !busy,
            label = { Text(stringResource(Res.string.send_address_label)) },
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = uiState.amount,
            onValueChange = onAmountChange,
            enabled = !busy,
            label = { Text(stringResource(Res.string.send_amount_label)) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(onClick = onPrepare, enabled = !busy) {
            val label = if (uiState.send is SendState.Preparing) Res.string.send_reviewing else Res.string.send_review
            Text(stringResource(label))
        }

        when (val send = uiState.send) {
            is SendState.Planned -> PlanCard(send, onConfirm, enabled = true)
            is SendState.Sending -> PlanCard(send.planned, onConfirm, enabled = false)
            is SendState.Failed -> {
                Text(
                    text = stringResource(Res.string.send_failed, send.message),
                    style = MaterialTheme.typography.bodyMedium,
                )
                PlanCard(send.planned, onConfirm, enabled = true, confirmLabel = Res.string.send_retry)
            }

            is SendState.Sent -> Text(
                text = stringResource(Res.string.send_sent, send.txid),
                style = MaterialTheme.typography.bodyMedium,
            )

            SendState.Idle, SendState.Preparing -> Unit
        }
    }
}

@Composable
private fun PlanCard(
    planned: SendState.Planned,
    onConfirm: () -> Unit,
    enabled: Boolean,
    confirmLabel: StringResource = Res.string.send_confirm,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(Res.string.plan_title), style = MaterialTheme.typography.labelMedium)
            PlanRow(stringResource(Res.string.plan_recipient), planned.addressSnapshot)
            PlanRow(stringResource(Res.string.plan_amount), zecAmount(planned.amountSnapshot))
            PlanRow(stringResource(Res.string.plan_fee), zecAmount(planned.plan.fee))
            PlanRow(stringResource(Res.string.plan_height), planned.plan.height.toString())
            planned.plan.inputs.forEach { input ->
                PlanRow(
                    label = stringResource(Res.string.plan_input, input.pool.name.lowercase()),
                    value = zecAmount(input.amount ?: 0L),
                )
            }
            planned.plan.outputs.forEach { output ->
                PlanRow(
                    label = stringResource(Res.string.plan_output, output.pool.name.lowercase()),
                    value = zecAmount(output.amount),
                )
            }
            Button(onClick = onConfirm, enabled = enabled && planned.plan.canSign) {
                Text(stringResource(if (enabled) confirmLabel else Res.string.send_sending))
            }
        }
    }
}

@Composable
private fun PlanRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(label, style = MaterialTheme.typography.bodySmall)
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            maxLines = 1,
            overflow = TextOverflow.MiddleEllipsis,
        )
    }
}
