package cash.p.zcash

import co.touchlab.kermit.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private const val DEFAULT_ACTIONS_PER_SYNC = 10_000
private const val DEFAULT_TRANSPARENT_LIMIT = 100
private const val DEFAULT_CHECKPOINT_AGE = 10_000
private const val DEFAULT_GAP_LIMIT = 20
private const val PROGRESS_SAMPLE_MS = 250L
private const val MEMPOOL_POLL_MS = 500L
private val logger = Logger.withTag("ZEC")

internal interface SyncBackend {
    val cancelRequested: Boolean

    suspend fun latestHeight(): Int

    suspend fun synchronize(
        accountIds: List<Int>,
        target: Int,
        actionsPerSync: Int,
        transparentLimit: Int,
        checkpointAge: Int,
    )

    suspend fun progress(): SyncProgress?

    suspend fun syncedHeight(accountIds: List<Int>): Int?

    fun onStart()

    fun onFinish()
}

internal fun syncFlow(
    accountIds: List<Int>,
    actionsPerSync: Int,
    transparentLimit: Int,
    checkpointAge: Int,
    mutex: Mutex,
    backend: SyncBackend,
): Flow<SyncState> = flow {
    emit(SyncState.Connecting)
    val target = try {
        backend.latestHeight()
    } catch (error: Throwable) {
        logSyncFailure(stage = "target", error)
        throw error
    }
    mutex.withLock {
        backend.onStart()
        val result = try {
            runNativeSync(accountIds, target, actionsPerSync, transparentLimit, checkpointAge, backend)
        } finally {
            backend.onFinish()
        }
        val terminal = emitTerminalState(accountIds, target, result.error, backend)
        logSyncTerminal(terminal, target, result.madeProgress)
    }
}.distinctUntilChanged()

private data class NativeSyncResult(
    val error: ZcashException?,
    val madeProgress: Boolean,
)

private suspend fun FlowCollector<SyncState>.runNativeSync(
    accountIds: List<Int>,
    target: Int,
    actionsPerSync: Int,
    transparentLimit: Int,
    checkpointAge: Int,
    backend: SyncBackend,
): NativeSyncResult = supervisorScope {
    val native = async {
        backend.synchronize(accountIds, target, actionsPerSync, transparentLimit, checkpointAge)
    }
    var madeProgress = false
    while (native.isActive) {
        delay(PROGRESS_SAMPLE_MS)
        if (!native.isActive) break
        backend.progress()?.let { progress ->
            val current = boundedSyncHeight(progress.height, target)
            if (!madeProgress) {
                madeProgress = true
                logger.d {
                    "sync progress current=$current target=$target actionsPerSync=$actionsPerSync"
                }
            }
            emit(SyncState.Syncing(current, target))
        }
    }
    val error = try {
        native.await()
        null
    } catch (error: ZcashException) {
        error
    }
    NativeSyncResult(error, madeProgress)
}

private suspend fun FlowCollector<SyncState>.emitTerminalState(
    accountIds: List<Int>,
    target: Int,
    error: ZcashException?,
    backend: SyncBackend,
): SyncState {
    val state = terminalSyncState(error, backend.cancelRequested)
    if (state != SyncState.Synced) {
        emit(state)
        return state
    }
    if (accountIds.isEmpty()) {
        emit(SyncState.Synced)
        return SyncState.Synced
    }

    val height = try {
        backend.syncedHeight(accountIds)
    } catch (error: ZcashException) {
        return SyncState.Failed(error).also { emit(it) }
    }
    height?.let { emit(SyncState.Syncing(boundedSyncHeight(it, target), target)) }
    return completedSyncState(height, target).also { emit(it) }
}

private fun boundedSyncHeight(height: Int, target: Int): Int = height.coerceAtMost(target)

private fun logSyncTerminal(state: SyncState, target: Int, madeProgress: Boolean) {
    when (state) {
        SyncState.Stopped -> logger.d { "sync cancelled target=$target" }
        SyncState.Synced -> if (madeProgress) logger.d { "sync completed target=$target" }
        is SyncState.Failed -> logSyncFailure(stage = "sync", state.error, target)
        SyncState.Connecting,
        is SyncState.Syncing,
            -> Unit
    }
}

private fun logSyncFailure(stage: String, error: Throwable, target: Int? = null) {
    val targetField = target?.let { " target=$it" }.orEmpty()
    logger.e { "sync failed stage=$stage category=${error.syncFailureCategory()}$targetField" }
}

private fun Throwable.syncFailureCategory(): String {
    val detail = message.orEmpty().lowercase()
    return when {
        "tls" in detail || "handshake" in detail -> "tls"
        "timeout" in detail || "timed out" in detail -> "timeout"
        "eof" in detail || "connection" in detail || "network" in detail || "socket" in detail -> "network"
        "sqlite" in detail || "database" in detail -> "database"
        else -> "other"
    }
}

private fun completedSyncState(height: Int?, target: Int): SyncState = when {
    height == null -> SyncState.Failed(ZcashException("Sync completed without the requested accounts"))
    height >= target -> SyncState.Synced
    else -> SyncState.Failed(ZcashException("Sync ended at block $height before target $target"))
}

/**
 * One open wallet database.
 *
 * Opening the same path twice shares a single native connection pool, so a second wallet on
 * the same file is not a second wallet — keep one instance per path. [close] releases this
 * object; the pool itself lives until the process ends.
 */
public class ZcashWallet private constructor(
    private val handle: Long,
    private val network: ZcashNetwork,
    syncBackendForTest: SyncBackend? = null,
) {

    @Volatile
    private var closed = false

    @Volatile
    private var cancelRequested = false

    @Volatile
    private var syncing = false

    private val nativeSyncBackend = object : SyncBackend {
        override val cancelRequested: Boolean
            get() = this@ZcashWallet.cancelRequested

        override suspend fun latestHeight(): Int = this@ZcashWallet.latestHeight()

        override suspend fun synchronize(
            accountIds: List<Int>,
            target: Int,
            actionsPerSync: Int,
            transparentLimit: Int,
            checkpointAge: Int,
        ) {
            withNative {
                ZcashJni.synchronize(
                    handle,
                    accountIds.toIntArray(),
                    target,
                    actionsPerSync,
                    transparentLimit,
                    checkpointAge,
                    false,
                )
            }
        }

        override suspend fun progress(): SyncProgress? =
            withNative { syncProgressOf(ZcashJni.syncProgress()) }

        override suspend fun syncedHeight(accountIds: List<Int>): Int? =
            this@ZcashWallet.syncedHeight(accountIds)

        override fun onStart() {
            this@ZcashWallet.cancelRequested = false
            syncing = true
        }

        override fun onFinish() {
            syncing = false
        }
    }

    private val syncBackend = syncBackendForTest ?: nativeSyncBackend

    /**
     * [key] is a seed phrase, a unified full viewing key, or a Sapling or transparent
     * extended key — never blank. A unified spending key is not accepted.
     *
     * A seed phrase or an imported spending-format key (`xprv`, a Sapling extended spending key)
     * yields a spending account, reported as `canSign = true`; every other key restores
     * watch-only (`canSign = false`). Only a seed phrase's spending key can currently be
     * derived on demand, with [ZcashSdk.deriveSpendingKey].
     *
     * [passphrase] is the BIP-39 passphrase (the "25th word") and applies to a seed phrase
     * only; the same passphrase must be passed to [ZcashSdk.deriveSpendingKey], otherwise
     * signing derives a key for a different wallet.
     */
    public suspend fun restoreAccount(
        name: String,
        key: String,
        birthHeight: Int = 0,
        pools: PoolSet = PoolSet.ALL,
        accountIndex: Int = 0,
        passphrase: String? = null,
    ): Int {
        require(key.isNotBlank()) { "Restore key must not be blank" }
        return newAccount(name, key, passphrase, birthHeight, pools, accountIndex)
    }

    public suspend fun accounts(): List<AccountInfo> =
        withNative { parseAccounts(ZcashJni.listAccounts(handle)) }

    public suspend fun deleteAccount(id: Int): Unit = withNative { ZcashJni.deleteAccount(handle, id) }

    /** Makes [id] the account the native layer works with by default. */
    public suspend fun selectAccount(id: Int): Unit = withNative { ZcashJni.setAccount(handle, id) }

    /**
     * Balance of [id], split into spendable and pending value.
     *
     * A note counts as available once it is [confirmations] blocks deep in the locally
     * scanned chain — the same cutoff a spend of it would have to clear.
     */
    public suspend fun balance(id: Int, confirmations: Int): PoolBalance {
        require(confirmations >= 0) { "Confirmations must not be negative: $confirmations" }
        return withNative { ZcashJni.balance(handle, id, confirmations).toPoolBalance() }
    }

    public suspend fun addresses(id: Int): Addresses =
        withNative { parseAddresses(ZcashJni.accountAddresses(handle, id)) }

    /** The unified full viewing key of [id], covering every pool the account holds keys for. */
    public suspend fun viewingKey(id: Int): String =
        withNative { ZcashJni.accountUfvk(handle, id) }

    /**
     * A fresh transparent address of [id] for one-time use, or `null` when the account has no
     * transparent key. The address [addresses] reports stays where it is.
     */
    public suspend fun nextTransparentAddress(id: Int): String? =
        withNative { ZcashJni.nextTransparentAddress(handle, id) }

    /**
     * Unspent value at [address] in zatoshi, as of the last sync — nothing is fetched here.
     *
     * Addresses outside [id] are simply worth nothing, not an error.
     */
    public suspend fun transparentBalance(id: Int, address: String): Long {
        require(address.isNotBlank()) { "Address must not be blank" }
        return withNative { ZcashJni.transparentBalance(handle, id, address) }
    }

    /**
     * Re-derives the transparent addresses [id] handed out before it was restored and stores those
     * the server knows a transaction for. A restore keeps the keys but not the address rows, so
     * money received on a one-time address stays invisible until this runs. Returns how many
     * addresses were added; it stops once it passes [gapLimit] unused addresses in a row.
     */
    public suspend fun discoverTransparentAddresses(id: Int, gapLimit: Int = DEFAULT_GAP_LIMIT): Int {
        val endHeight = latestHeight()
        return withNative { ZcashJni.discoverTransparentAddresses(handle, id, endHeight, gapLimit) }
    }

    /**
     * A conservative lower bound on what [id] can spend using only [pools], in zatoshi.
     *
     * Not the exact maximum: the amount stays fundable whichever pool the recipient's address
     * belongs to, so a send that stays inside [pools] can afford slightly more.
     */
    public suspend fun maxSpendable(id: Int, pools: PoolSet, confirmations: Int): Long {
        require(confirmations >= 0) { "Confirmations must not be negative: $confirmations" }
        return withNative { ZcashJni.maxSpendable(handle, id, confirmations, pools.mask) }
    }

    /** Transactions already written to the local database — a sync is what adds new ones. */
    public suspend fun transactions(id: Int): List<Transaction> =
        withNative { parseTransactions(ZcashJni.listTransactions(handle, id)) }

    /** Chain tip as the configured server reports it. */
    public suspend fun latestHeight(): Int = withNative { ZcashJni.latestHeight(handle) }

    /** Builds an unsigned package for [recipients]. Account-scoped, like [balance] and [addresses]. */
    public suspend fun prepare(
        account: Int,
        recipients: List<Recipient>,
        options: PaymentOptions = PaymentOptions(),
    ): PreparedTransaction = withNative {
        val bytes = ZcashJni.prepare(
            handle,
            account,
            encodeRecipients(recipients),
            options.sourcePools.mask.toByte(),
            options.recipientPaysFee,
            options.smartTransparent,
            options.confirmations,
            options.hardwareSigning,
        )
        PreparedTransaction(bytes)
    }

    /** What [transaction] would spend and send, without signing or broadcasting it. */
    public suspend fun plan(transaction: PreparedTransaction): TransactionPlan =
        withNative { parseTransactionPlan(ZcashJni.transactionPlan(handle, transaction.bytes)) }

    /**
     * Signs [transaction] on behalf of [account].
     *
     * [transaction] must be the one [plan] was called on, built for [account] and for the same
     * set of pools: the signer checks each pool separately and rejects a bundle whose spends the
     * key does not cover. [spendingKey] must belong to [account]; see [send] for the
     * key-handling contract.
     */
    public suspend fun sign(
        account: Int,
        transaction: PreparedTransaction,
        spendingKey: ByteArray,
    ): PreparedTransaction = withNative {
        PreparedTransaction(
            ZcashJni.signTransaction(handle, account, transaction.bytes, spendingKey),
        )
    }

    /** The final wire-format transaction bytes, ready for [broadcast]. */
    public suspend fun extract(transaction: PreparedTransaction): ByteArray =
        withNative { ZcashJni.extractTransaction(transaction.bytes) }

    /**
     * The JSON payload an external signer (e.g. Trezor) needs to review and sign [transaction]'s
     * transparent bundle. [transaction] must come from a [prepare] with `hardwareSigning = true`.
     *
     * Stateless: only this wallet's own [network] is used, no account and no database access.
     */
    public suspend fun transparentSigningRequest(transaction: PreparedTransaction): TransparentSigningRequest =
        withNative {
            parseTransparentSigningRequest(ZcashJni.transparentSigningRequest(network.coin, transaction.bytes))
        }

    /**
     * Applies device-produced ECDSA signatures to [transaction]'s transparent inputs and
     * finalizes them, ready for [extract].
     *
     * [indices] and [sigs] are parallel arrays: `sigs[i]` signs the transparent input at
     * `indices[i]`. Structural mistakes — mismatched sizes, a negative or duplicate index, an
     * empty signature — are rejected here, before the native call; DER and sighash validity stay
     * native.
     */
    public suspend fun applyTransparentSignatures(
        transaction: PreparedTransaction,
        indices: IntArray,
        sigs: Array<ByteArray>,
    ): PreparedTransaction {
        require(indices.size == sigs.size) {
            "indices and sigs must have the same size: ${indices.size} != ${sigs.size}"
        }
        require(indices.none { it < 0 }) { "indices must not contain a negative index" }
        require(indices.toSet().size == indices.size) { "indices must not contain a duplicate index" }
        require(sigs.none { it.isEmpty() }) { "sigs must not contain an empty signature" }
        return withNative {
            PreparedTransaction(ZcashJni.applyTransparentSignatures(transaction.bytes, indices, sigs))
        }
    }

    /**
     * Reserves wallet-owned inputs before a caller starts network I/O. Idempotent for the same tx.
     * Pass `requireOwnInputs = false` for a transaction of unknown origin: it then reserves nothing
     * instead of being refused for spending no input of this account.
     */
    public suspend fun reserveForBroadcast(
        account: Int,
        rawTransaction: ByteArray,
        requireOwnInputs: Boolean = true,
    ): Unit = withNative {
        ZcashJni.reserveForBroadcast(handle, account, rawTransaction, requireOwnInputs)
    }

    /** Hands [rawTransaction] to the node and reports its verdict without interpreting it. */
    public suspend fun broadcast(
        account: Int,
        rawTransaction: ByteArray,
        height: Int,
        requireOwnInputs: Boolean = true,
    ): BroadcastResult = withNative {
        parseBroadcastResult(
            ZcashJni.broadcastTransaction(handle, account, height, rawTransaction, requireOwnInputs),
        )
    }

    /**
     * The full send path: prepare, plan (for its height), sign, extract, broadcast. Returns
     * the txid.
     *
     * [spendingKey] must cover every pool [account] holds a viewing key for: a key from
     * another seed or account index, and a partial key missing one of the account's pools,
     * are both rejected rather than signing part of the transaction. The SDK stores no
     * spending key, so holding, passing and wiping these bytes is the caller's job.
     */
    public suspend fun send(
        account: Int,
        recipients: List<Recipient>,
        spendingKey: ByteArray,
        options: PaymentOptions = PaymentOptions(),
    ): String {
        val prepared = prepare(account, recipients, options)
        val height = plan(prepared).height
        val signed = sign(account, prepared, spendingKey)
        val raw = extract(signed)
        val result = broadcast(account, raw, height)
        if (!result.accepted) {
            throw ZcashException("Broadcast rejected (${result.errorCode}): ${result.message}")
        }
        return result.message
    }

    /** Where the Orchard → Ironwood migration currently stands for [account]. */
    public suspend fun migrationStatus(account: Int): MigrationStatus =
        withNative { parseMigrationStatus(ZcashJni.migrationStatus(handle, account)) }

    /**
     * Runs one step of the migration, signing and broadcasting on its own.
     *
     * The protocol moves one note per transaction, so the caller repeats this until the
     * reported phase is [MigrationPhase.COMPLETE] and paces the loop itself.
     *
     * [spendingKey] must belong to [account]; see [send] for the key-handling contract.
     */
    public suspend fun migrationStep(account: Int, spendingKey: ByteArray): MigrationStep =
        withNative { parseMigrationStep(ZcashJni.migrationStep(handle, account, spendingKey)) }

    /**
     * Scans [accountIds] up to the current chain tip.
     *
     * The native sync is one blocking call, so cancelling collection of this flow does not
     * stop it — only [cancelSync] does, and it stops whichever sync is running process-wide.
     * An empty [accountIds] is nothing to do and completes as [SyncState.Synced].
     */
    public fun sync(
        accountIds: List<Int>,
        actionsPerSync: Int = DEFAULT_ACTIONS_PER_SYNC,
        transparentLimit: Int = DEFAULT_TRANSPARENT_LIMIT,
        checkpointAge: Int = DEFAULT_CHECKPOINT_AGE,
    ): Flow<SyncState> = syncFlow(
        accountIds = accountIds,
        actionsPerSync = actionsPerSync,
        transparentLimit = transparentLimit,
        checkpointAge = checkpointAge,
        mutex = ZcashSdk.syncMutex,
        backend = syncBackend,
    )

    /**
     * Stops the running sync, whichever wallet started it: rlz cancels globally. Only the wallet
     * that asked reports [SyncState.Stopped]; another wallet's sync ends as [SyncState.Failed].
     */
    public suspend fun cancelSync() {
        cancelRequested = true
        withContext(Dispatchers.IO) { mapNativeError { ZcashJni.cancelSync() } }
    }

    /**
     * Unconfirmed transactions the configured server sees, for every account of this wallet.
     *
     * The subscription is process-wide, so a second collection while one is running fails.
     * Nothing here is written to the database: these events live only as long as they are
     * collected. Collection ends when the native run does — cleanly on [stopMempool], with a
     * [ZcashException] when reading failed — and leaving the flow always stops the run.
     */
    public fun mempool(): Flow<MempoolEvent> = flow {
        withNative { ZcashJni.mempoolStart(handle) }
        try {
            while (true) {
                val json = withNative { ZcashJni.mempoolNext(MEMPOOL_POLL_MS) } ?: continue
                emit(parseMempoolEvent(json) ?: break)
            }
        } finally {
            withContext(NonCancellable) { stopMempool() }
        }
    }

    /** Stops the subscription, returning only after the native reader has actually stopped. */
    public suspend fun stopMempool() {
        withContext(Dispatchers.IO) { mapNativeError { ZcashJni.mempoolStop() } }
    }

    /** Releases the handle. Calling it again, or any other method afterwards, is safe. */
    public suspend fun close() {
        if (closed) return
        if (syncing) cancelSync()
        stopMempool()
        closed = true
        withContext(Dispatchers.IO) { mapNativeError { ZcashJni.close(handle) } }
    }

    private suspend fun newAccount(
        name: String,
        key: String,
        passphrase: String?,
        birthHeight: Int,
        pools: PoolSet,
        accountIndex: Int,
    ): Int {
        require(!pools.isEmpty) { "An account needs at least one pool" }
        return withNative {
            ZcashJni.newAccount(handle, name, key, passphrase, birthHeight, pools.mask, accountIndex)
        }
    }

    /** The height every synced account has reached, so [SyncState.Synced] reports the real tip. */
    private suspend fun syncedHeight(accountIds: List<Int>): Int? =
        accounts().filter { it.id in accountIds }.minOfOrNull { it.height }

    private suspend fun <T> withNative(block: () -> T): T = withContext(Dispatchers.IO) {
        if (closed) throw ZcashException("Wallet is closed")
        mapNativeError(block)
    }

    public companion object {

        internal fun forSyncTest(backend: SyncBackend): ZcashWallet =
            ZcashWallet(0, ZcashNetwork.MAIN, backend)

        /**
         * [ZcashSdk.initialize] must have run first.
         *
         * [dbKey] is the SQLCipher raw key: exactly 32 bytes, or `null` to leave the database
         * unencrypted. The SDK neither generates, derives, nor stores it — supplying and keeping
         * it is the caller's job. A lost key means rescanning from the account birthday height.
         */
        public suspend fun open(
            dbPath: String,
            network: ZcashNetwork,
            server: ServerConfig,
            dbKey: ByteArray? = null,
        ): ZcashWallet = withContext(Dispatchers.IO) {
            val handle = mapNativeError {
                ZcashJni.open(
                    dbPath,
                    dbKey,
                    network.coin,
                    server.url,
                    server.type.id,
                    server.transport.id,
                    server.proxy,
                )
            }
            ZcashWallet(handle, network)
        }
    }
}
