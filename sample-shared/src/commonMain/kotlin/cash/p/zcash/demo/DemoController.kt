package cash.p.zcash.demo

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import cash.p.zcash.Recipient
import cash.p.zcash.ServerConfig
import cash.p.zcash.SyncState
import cash.p.zcash.Transaction
import cash.p.zcash.ZcashNetwork
import cash.p.zcash.ZcashSdk
import cash.p.zcash.deriveSpendingKey
import cash.p.zcash.ZcashWallet
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch

private const val ACCOUNT_NAME = "demo"
private const val DATABASE_FILE = "demo.db"

/** Blocks a note must be buried under before it counts as spendable. */
private const val CONFIRMATIONS = 10

class DemoController(
    private val dataDir: String,
    private val scope: CoroutineScope,
) {

    internal var uiState by mutableStateOf(DemoUiState())
        private set

    private var wallet: ZcashWallet? = null
    private var syncJob: Job? = null

    /** Opens the wallet once per controller lifetime — a second call would open a second handle. */
    fun start() {
        if (DemoConfig.WORDS.isBlank()) {
            uiState = uiState.copy(phase = DemoPhase.NeedsSeed)
            return
        }
        scope.launch {
            runGuarded(DemoPhase.Error) {
                ZcashSdk.initialize(dataDir)
                val opened = ZcashWallet.open(
                    dbPath = "$dataDir/$DATABASE_FILE",
                    network = ZcashNetwork.MAIN,
                    server = ServerConfig(DemoConfig.SERVER_URL),
                    dbKey = DemoConfig.DB_KEY.hexToByteArray(),
                )
                wallet = opened
                val id = opened.accounts().firstOrNull()?.id ?: opened.restoreAccount(
                    name = ACCOUNT_NAME,
                    key = DemoConfig.WORDS,
                    birthHeight = DemoConfig.BIRTHDAY,
                )
                uiState = uiState.copy(phase = DemoPhase.Ready, accountId = id)
                load(opened, id)
            }
        }
    }

    fun sync() {
        val wallet = wallet ?: return
        val id = uiState.accountId ?: return
        if (syncJob?.isActive == true) return
        syncJob = scope.launch {
            runGuarded {
                try {
                    wallet.sync(listOf(id)).collect { state ->
                        uiState = uiState.copy(syncState = state, chainTip = state.target ?: uiState.chainTip)
                        if (state is SyncState.Synced) load(wallet, id)
                    }
                } finally {
                    // The flow may end mid-progress — cancelled or failed — and busy would stick forever.
                    if (uiState.syncState.busy) uiState = uiState.copy(syncState = SyncState.Stopped)
                }
            }
        }
    }

    fun cancelSync() {
        val wallet = wallet ?: return
        scope.launch { runGuarded { wallet.cancelSync() } }
    }

    fun refresh() {
        val wallet = wallet ?: return
        val id = uiState.accountId ?: return
        scope.launch { runGuarded { load(wallet, id) } }
    }

    /** Wipes the account's scan state and restores it from the same seed; the database file stays. */
    fun reset() {
        val wallet = wallet ?: return
        val id = uiState.accountId ?: return
        if (uiState.syncing) return
        scope.launch {
            runGuarded {
                wallet.cancelSync()
                syncJob?.cancelAndJoin()
                syncJob = null
                wallet.deleteAccount(id)
                val restored = wallet.restoreAccount(
                    name = ACCOUNT_NAME,
                    key = DemoConfig.WORDS,
                    birthHeight = DemoConfig.BIRTHDAY,
                )
                uiState = DemoUiState(phase = DemoPhase.Ready, accountId = restored)
                load(wallet, restored)
            }
        }
    }

    fun onAddressChange(value: String) {
        uiState = uiState.copy(address = value, send = uiState.send.discardedOnEdit(), error = null)
    }

    fun onAmountChange(value: String) {
        uiState = uiState.copy(amount = value, send = uiState.send.discardedOnEdit(), error = null)
    }

    fun preparePayment() {
        val wallet = wallet ?: return
        val id = uiState.accountId ?: return
        val address = uiState.address.trim()
        val amount = parseZatoshi(uiState.amount)
        if (address.isEmpty()) {
            uiState = uiState.copy(error = DemoError.EmptyAddress)
            return
        }
        if (amount == null || amount <= 0L) {
            uiState = uiState.copy(error = DemoError.InvalidAmount)
            return
        }
        uiState = uiState.copy(send = SendState.Preparing, error = null)
        scope.launch {
            runGuarded {
                val prepared = wallet.prepare(id, listOf(Recipient(address, amount)))
                val plan = wallet.plan(prepared)
                // The form may have moved while prepare was suspended: only send what is shown.
                val unchanged = uiState.address.trim() == address && parseZatoshi(uiState.amount) == amount
                uiState = uiState.copy(
                    send = if (unchanged) SendState.Planned(prepared, plan, address, amount) else SendState.Idle,
                )
            }
        }
    }

    fun confirmPayment() {
        val wallet = wallet ?: return
        val id = uiState.accountId ?: return
        val planned = uiState.send.plannedOrNull() ?: return
        uiState = uiState.copy(send = SendState.Sending(planned), error = null)
        scope.launch {
            runGuarded {
                val spendingKey = ZcashSdk.deriveSpendingKey(DemoConfig.WORDS, ZcashNetwork.MAIN)
                val signed = try {
                    wallet.sign(id, planned.prepared, spendingKey)
                } finally {
                    spendingKey.fill(0)
                }
                val raw = wallet.extract(signed)
                val result = wallet.broadcast(raw, planned.plan.height)
                if (!result.accepted) {
                    uiState = uiState.copy(send = SendState.Failed(planned, result.message))
                    return@runGuarded
                }
                uiState = uiState.copy(send = SendState.Sent(result.message), address = "", amount = "")
                load(wallet, id)
            }
        }
    }

    fun dismissError() {
        uiState = uiState.copy(error = null)
    }

    private suspend fun load(wallet: ZcashWallet, id: Int) {
        uiState = uiState.copy(
            balance = wallet.balance(id, confirmations = CONFIRMATIONS),
            addresses = wallet.addresses(id),
            transactions = wallet.transactions(id).sortedByDescending(Transaction::height),
        )
    }

    /**
     * The single error contract: without it a native failure would reach a scope with no
     * handler and take the process down.
     */
    private suspend fun runGuarded(failurePhase: DemoPhase = DemoPhase.Ready, block: suspend () -> Unit) {
        try {
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            val message = e.message ?: e.toString()
            uiState = uiState.copy(
                phase = failurePhase,
                error = DemoError.Native(message),
                send = uiState.send.recovered(message),
            )
        }
    }
}

private val SyncState.target: Int?
    get() = (this as? SyncState.Syncing)?.target

private fun SendState.plannedOrNull(): SendState.Planned? = when (this) {
    is SendState.Planned -> this
    is SendState.Failed -> planned
    else -> null
}

/** An edit invalidates a prepared package, but must not interrupt a call already in flight. */
private fun SendState.discardedOnEdit(): SendState =
    if (this is SendState.Preparing || this is SendState.Sending) this else SendState.Idle

/** A failure never leaves the flow busy; a package that was already built survives it. */
private fun SendState.recovered(message: String): SendState = when (this) {
    is SendState.Preparing -> SendState.Idle
    is SendState.Sending -> SendState.Failed(planned, message)
    else -> this
}
