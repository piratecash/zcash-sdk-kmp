package cash.p.zcash.demo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import cash.p.zcash.Addresses
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.action_copy
import cash.p.zcash.demo.resources.address_orchard
import cash.p.zcash.demo.resources.address_sapling
import cash.p.zcash.demo.resources.address_transparent
import cash.p.zcash.demo.resources.address_unified
import cash.p.zcash.demo.resources.receive_not_loaded
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.stringResource

@Composable
internal fun ReceiveScreen(addresses: Addresses?) {
    if (addresses == null) {
        Text(
            text = stringResource(Res.string.receive_not_loaded),
            modifier = Modifier.padding(24.dp),
            style = MaterialTheme.typography.bodyLarge,
        )
        return
    }
    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        AddressCard(Res.string.address_unified, addresses.unified)
        AddressCard(Res.string.address_sapling, addresses.sapling)
        AddressCard(Res.string.address_orchard, addresses.orchard)
        AddressCard(Res.string.address_transparent, addresses.transparent)
    }
}

@Composable
private fun AddressCard(title: StringResource, address: String?) {
    if (address.isNullOrBlank()) return
    val clipboard = LocalClipboardManager.current
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(title), style = MaterialTheme.typography.labelMedium)
            Text(address, style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = { clipboard.setText(AnnotatedString(address)) }) {
                Text(stringResource(Res.string.action_copy))
            }
        }
    }
}
