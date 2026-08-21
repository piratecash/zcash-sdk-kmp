package cash.p.zcash

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.FlowCollector
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

private const val DEFAULT_ACTIONS_PER_SYNC = 100_000
private const val DEFAULT_TRANSPARENT_LIMIT = 100
private const val DEFAULT_CHECKPOINT_AGE = 10_000
private const val DEFAULT_GAP_LIMIT = 20
private const val PROGRESS_SAMPLE_MS = 250L
private const val MEMPOOL_POLL_MS = 500L

/**
 * One open wallet database.
 *
 * Opening the same path twice shares a single native connection pool, so a second wallet on
 * the same file is not a second wallet — keep one instance per path. [close] releases this
 * object; the pool itself lives until the process ends.
 */
public class ZcashWallet private constructor(private val handle: Long) {

    @Volatile
    private var closed = false

    @Volatile
    private var cancelRequested = false

    @Volatile
    private var syncing = false

    /**
     * [key] is a seed phrase, a unified full viewing key, or a Sapling or transparent
     * extended key — never blank. A unified spending key is not accepted.
     *
     * Only a seed phrase yields a spendable account: its spending key is derived on demand
     * with [ZcashSdk.deriveSpendingKey]. Every other key restores watch-only, and such an
     * account reports `canSign = false`.
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
        )
        PreparedTransaction(bytes)
    }

    /** What [transaction] would spend and send, without signing or broadcasting it. */
    public suspend fun plan(transaction: PreparedTransaction): TransactionPlan =
        withNative { parseTransactionPlan(ZcashJni.transactionPlan(handle, transaction.bytes)) }

    /**
     * Signs [transaction] on behalf of [account].
     *
     * [spendingKey] must belong to [account]: a key derived from another seed or another
     * account index is rejected, never silently ignored. The SDK stores no spending key, so
     * holding, passing and wiping these bytes is the caller's job.
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

    /** Hands [rawTransaction] to the node and reports its verdict without interpreting it. */
    public suspend fun broadcast(rawTransaction: ByteArray, height: Int): BroadcastResult =
        withNative { parseBroadcastResult(ZcashJni.broadcastTransaction(handle, height, rawTransaction)) }

    /**
     * The full send path: prepare, plan (for its height), sign, extract, broadcast. Returns
     * the txid.
     *
     * [spendingKey] must belong to [account]: a key derived from another seed or another
     * account index is rejected, never silently ignored. The SDK stores no spending key, so
     * holding, passing and wiping these bytes is the caller's job.
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
        val result = broadcast(raw, height)
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
    ): Flow<SyncState> = flow {
        emit(SyncState.Connecting)
        val target = latestHeight()
        ZcashSdk.syncMutex.withLock {
            cancelRequested = false
            syncing = true
            val error = try {
                runSync(accountIds, target, actionsPerSync, transparentLimit, checkpointAge)
            } finally {
                syncing = false
            }
            val state = terminalSyncState(error, cancelRequested)
            if (state == SyncState.Synced) {
                // A close() racing this last read must not turn a finished sync into a failure.
                val height = try {
                    syncedHeight(accountIds)
                } catch (_: ZcashException) {
                    null
                }
                height?.let { emit(SyncState.Syncing(it, target)) }
            }
            emit(state)
        }
    }

    /** Runs the blocking native sync while sampling its progress; returns what it failed with. */
    private suspend fun FlowCollector<SyncState>.runSync(
        accountIds: List<Int>,
        target: Int,
        actionsPerSync: Int,
        transparentLimit: Int,
        checkpointAge: Int,
    ): ZcashException? = supervisorScope {
        val native = async {
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
        while (native.isActive) {
            delay(PROGRESS_SAMPLE_MS)
            syncProgressOf(ZcashJni.syncProgress())?.let { emit(SyncState.Syncing(it.height, target)) }
        }
        try {
            native.await()
            null
        } catch (e: ZcashException) {
            e
        }
    }

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
            ZcashWallet(handle)
        }
    }
}
