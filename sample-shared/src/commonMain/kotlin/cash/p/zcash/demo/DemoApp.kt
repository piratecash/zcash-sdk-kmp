package cash.p.zcash.demo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import cash.p.zcash.demo.resources.Res
import cash.p.zcash.demo.resources.account_balance_wallet
import cash.p.zcash.demo.resources.call_made
import cash.p.zcash.demo.resources.call_received
import cash.p.zcash.demo.resources.error_empty_address
import cash.p.zcash.demo.resources.error_invalid_amount
import cash.p.zcash.demo.resources.error_open_failed
import cash.p.zcash.demo.resources.needs_seed
import cash.p.zcash.demo.resources.opening_wallet
import cash.p.zcash.demo.resources.receipt_long
import cash.p.zcash.demo.resources.tab_balance
import cash.p.zcash.demo.resources.tab_receive
import cash.p.zcash.demo.resources.tab_send
import cash.p.zcash.demo.resources.tab_transactions
import org.jetbrains.compose.resources.DrawableResource
import org.jetbrains.compose.resources.StringResource
import org.jetbrains.compose.resources.painterResource
import org.jetbrains.compose.resources.stringResource

private enum class DemoTab(val title: StringResource, val icon: DrawableResource) {
    Balance(Res.string.tab_balance, Res.drawable.account_balance_wallet),
    Transactions(Res.string.tab_transactions, Res.drawable.receipt_long),
    Send(Res.string.tab_send, Res.drawable.call_made),
    Receive(Res.string.tab_receive, Res.drawable.call_received),
}

@Composable
fun DemoApp(controller: DemoController) {
    MaterialTheme {
        val state = controller.uiState
        var tab by remember { mutableStateOf(DemoTab.Balance) }
        val snackbarHostState = remember { SnackbarHostState() }
        val errorText = state.error?.text()

        LaunchedEffect(errorText) {
            val message = errorText?.takeIf { state.phase != DemoPhase.Error } ?: return@LaunchedEffect
            snackbarHostState.showSnackbar(message)
            controller.dismissError()
        }

        Scaffold(
            snackbarHost = { SnackbarHost(snackbarHostState) },
            bottomBar = {
                NavigationBar {
                    DemoTab.entries.forEach { entry ->
                        val title = stringResource(entry.title)
                        NavigationBarItem(
                            selected = tab == entry,
                            onClick = { tab = entry },
                            icon = { Icon(painterResource(entry.icon), contentDescription = null) },
                            label = { Text(title) },
                        )
                    }
                }
            },
        ) { padding ->
            Box(Modifier.fillMaxSize().padding(padding)) {
                when (state.phase) {
                    DemoPhase.NeedsSeed -> Message(stringResource(Res.string.needs_seed))
                    DemoPhase.Opening -> Message(stringResource(Res.string.opening_wallet))
                    DemoPhase.Error -> Message(errorText ?: stringResource(Res.string.error_open_failed))
                    DemoPhase.Ready -> when (tab) {
                        DemoTab.Balance -> BalanceScreen(
                            uiState = state,
                            onSync = controller::sync,
                            onCancelSync = controller::cancelSync,
                            onRefresh = controller::refresh,
                            onReset = controller::reset,
                        )

                        DemoTab.Transactions -> TransactionsScreen(state.transactions)
                        DemoTab.Send -> SendScreen(
                            uiState = state,
                            onAddressChange = controller::onAddressChange,
                            onAmountChange = controller::onAmountChange,
                            onPrepare = controller::preparePayment,
                            onConfirm = controller::confirmPayment,
                        )

                        DemoTab.Receive -> ReceiveScreen(state.addresses)
                    }
                }
            }
        }
    }
}

@Composable
private fun DemoError.text(): String = when (this) {
    DemoError.EmptyAddress -> stringResource(Res.string.error_empty_address)
    DemoError.InvalidAmount -> stringResource(Res.string.error_invalid_amount)
    is DemoError.Native -> message
}

@Composable
private fun Message(text: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(text, style = MaterialTheme.typography.bodyLarge)
    }
}
