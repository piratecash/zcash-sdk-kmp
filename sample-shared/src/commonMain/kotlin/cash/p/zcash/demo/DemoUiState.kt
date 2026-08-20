package cash.p.zcash.demo

import cash.p.zcash.Addresses
import cash.p.zcash.PoolBalance
import cash.p.zcash.PreparedTransaction
import cash.p.zcash.SyncState
import cash.p.zcash.Transaction
import cash.p.zcash.TransactionPlan

internal enum class DemoPhase { NeedsSeed, Opening, Ready, Error }

/** Errors travel as data: only the UI layer knows which string resource describes them. */
internal sealed interface DemoError {
    data object EmptyAddress : DemoError
    data object InvalidAmount : DemoError
    data class Native(val message: String) : DemoError
}

/**
 * A prepared package may only be broadcast exactly as it was shown: [Planned] carries the
 * address and amount it was built from, and any edit of the form drops it back to [Idle].
 */
internal sealed interface SendState {
    data object Idle : SendState
    data object Preparing : SendState
    data class Planned(
        val prepared: PreparedTransaction,
        val plan: TransactionPlan,
        val addressSnapshot: String,
        val amountSnapshot: Long,
    ) : SendState

    data class Sending(val planned: Planned) : SendState
    data class Sent(val txid: String) : SendState
    data class Failed(val planned: Planned, val message: String) : SendState
}

internal data class DemoUiState(
    val phase: DemoPhase = DemoPhase.Opening,
    val syncState: SyncState = SyncState.Stopped,
    val balance: PoolBalance? = null,
    val addresses: Addresses? = null,
    val transactions: List<Transaction> = emptyList(),
    val accountId: Int? = null,
    val chainTip: Int? = null,
    val address: String = "",
    val amount: String = "",
    val send: SendState = SendState.Idle,
    val error: DemoError? = null,
)

internal val SyncState.busy: Boolean
    get() = this is SyncState.Connecting || this is SyncState.Syncing

internal val DemoUiState.syncing: Boolean
    get() = syncState.busy

internal val DemoUiState.sendBusy: Boolean
    get() = send is SendState.Preparing || send is SendState.Sending
