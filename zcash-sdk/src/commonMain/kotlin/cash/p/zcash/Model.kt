package cash.p.zcash

/**
 * One pool's unspent value in zatoshi, split by whether it can be spent yet.
 *
 * [changePending] is change coming back from own spends, [valuePending] is incoming payments.
 */
public data class Balance(
    val available: Long = 0L,
    val changePending: Long = 0L,
    val valuePending: Long = 0L,
) {
    public val pending: Long get() = changePending + valuePending

    public val total: Long get() = available + pending
}

/** Per-pool balances of a single account, in zatoshi. */
public data class PoolBalance(private val byPool: Map<Pool, Balance>) {

    public operator fun get(pool: Pool): Balance = byPool[pool] ?: Balance()

    public val available: Long get() = byPool.values.sumOf { it.available }

    public val total: Long get() = byPool.values.sumOf { it.total }

    public val shielded: Long get() = total - get(Pool.TRANSPARENT).total
}

/**
 * Every address type of one account. One account holds them all, so unified, sapling
 * and transparent never cost separate databases or separate chain scans.
 */
public data class Addresses(
    val unified: String?,
    val sapling: String?,
    val orchard: String?,
    val transparent: String?,
    val diversifierIndex: Int,
)

/** The kinds of address the SDK can decode. A UA is [UNIFIED] whatever it holds. */
public enum class ZcashAddressKind {
    TRANSPARENT,
    SAPLING,
    UNIFIED,

    /** ZIP-320 transparent-source-only address. */
    TEX,
}

public sealed interface SyncState {
    public data object Stopped : SyncState
    public data object Connecting : SyncState
    public data class Syncing(val current: Int, val target: Int) : SyncState
    public data object Synced : SyncState
    public data class Failed(val error: Throwable) : SyncState
}

/** Zcash network, in the coin numbering the native layer uses. */
public enum class ZcashNetwork(internal val coin: Byte) {
    MAIN(0),
    TEST(1),
    REGTEST(2),
    ZSA_REGTEST(3),
}

/** Lightwalletd speaks gRPC and Zebra speaks JSON-RPC; the URL alone does not say which. */
public enum class ServerType(internal val id: Byte) {
    LIGHTWALLETD(0),
    ZEBRA(1),
}

/** How the server is reached. Nym is not built into this SDK, so its transport id has no entry. */
public enum class Transport(internal val id: Byte) {
    DIRECT(0),
    TOR(1),
    PROXY(3),
}

public data class ServerConfig(
    val url: String,
    val type: ServerType = ServerType.LIGHTWALLETD,
    val transport: Transport = Transport.DIRECT,
    val proxy: String = "",
)

/** One account as the wallet database holds it. [height] is how far that account has synced. */
public data class AccountInfo(
    val id: Int,
    val name: String,
    val birthHeight: Int,
    val accountIndex: Int,
    val diversifierIndex: Int,
    val position: Int,
    val height: Int,
    val time: Long,
    val balance: Long,
    val hidden: Boolean,
    val enabled: Boolean,
    val internal: Boolean,
    val hardwareWallet: Boolean,
)

/** The last block a running sync reported. */
public data class SyncProgress(val height: Int, val time: Long)

/** One payment output. [pools] picks which pool receives it; `null` derives that from the address. */
public data class Recipient(
    val address: String,
    val amount: Long,
    val pools: PoolSet? = null,
    val memo: String? = null,
)

public data class PaymentOptions(
    val sourcePools: PoolSet = PoolSet.ALL,
    val recipientPaysFee: Boolean = false,
    val smartTransparent: Boolean = false,
)

/** Opaque, packed transaction state as it moves through prepare → plan → sign → extract → broadcast. */
@JvmInline
public value class PreparedTransaction(public val bytes: ByteArray)

public data class PlanInput(val pool: Pool, val amount: Long?, val assetName: String)

public data class PlanOutput(val pool: Pool, val amount: Long, val address: String, val assetName: String)

/** One entry of the local transaction history. [value] is signed: negative when funds leave. */
public data class Transaction(
    val id: Int,
    val txid: String,
    val height: Int,
    val time: Long,
    val value: Long,
    val memo: String?,
    val fee: Long,
    /** Sum of the notes this account received here, before change is netted out of [value]. */
    val totalReceived: Long,
    val isChange: Boolean,
    /** First output that is not ours; null until transaction details are fetched. */
    val recipient: String?,
)

/** What [ZcashWallet.plan] reports before a transaction is signed or broadcast. */
public data class TransactionPlan(
    val height: Int,
    val inputs: List<PlanInput>,
    val outputs: List<PlanOutput>,
    val fee: Long,
    val canSign: Boolean,
    val canBroadcast: Boolean,
)

/**
 * The outcome of a finished sync. The native layer reports every failure — cancellation
 * included — through its error channel, so an absent error is the only success signal.
 */
internal fun terminalSyncState(error: Throwable?, cancelRequested: Boolean): SyncState = when {
    error == null -> SyncState.Synced
    cancelRequested -> SyncState.Stopped
    else -> SyncState.Failed(error)
}

/** Unpacks the native progress word: height in the high bits, block time in the low ones. */
internal fun syncProgressOf(packed: Long): SyncProgress? = when (packed) {
    0L -> null
    else -> SyncProgress(height = (packed ushr Int.SIZE_BITS).toInt(), time = packed and 0xFFFF_FFFFL)
}

/**
 * Where the Orchard → Ironwood migration stands. Notes are first split into standard
 * denominations ([MigrationPhase.SPLITTING]), then moved one at a time
 * ([MigrationPhase.MIGRATING]), so a single step never finishes the whole pool.
 */
public data class MigrationStatus(
    val phase: MigrationPhase,
    val standardNotes: Int,
    val nonStandardNotes: Int,
    val migratedNotes: Int,
)

public enum class MigrationPhase {
    SPLITTING,
    MIGRATING,
    COMPLETE,
}

/**
 * What one [ZcashWallet.migrationStep] did. [fee] is zero and [txid] null for the events
 * that broadcast nothing.
 */
public data class MigrationStep(
    val event: MigrationEvent,
    val fee: Long,
    val txid: String?,
    val status: MigrationStatus,
)

public enum class MigrationEvent {
    SPLIT_COMPLETE,
    MIGRATE_COMPLETE,
    COMPLETE,

    /** Nothing to do yet: the migration is waiting for its next anchor block. */
    NOTHING_TO_DO,
}

/**
 * The node's verdict on a broadcast. [errorCode] `0` means the transaction was accepted and
 * [message] is its txid; anything else is a rejection and [message] is the node's reason.
 */
public data class BroadcastResult(
    val errorCode: Int,
    val message: String,
) {
    public val accepted: Boolean get() = errorCode == 0
}

/**
 * One observation of the mempool. The flow ends when the native run stops — cleanly on
 * cancellation, with a [ZcashException] when reading failed.
 */
public sealed interface MempoolEvent {

    /**
     * A new observation epoch opened at [height]. It is NOT a claim that anything was mined:
     * the height is read before the stream reopens, so a transaction seen in the previous
     * epoch may still be unmined and still in the mempool.
     */
    public data class Epoch(val height: Int) : MempoolEvent

    /** A transaction sitting in the mempool that decrypted for at least one local account. */
    public data class Unconfirmed(
        val txid: String,
        val amounts: List<MempoolAmount>,
        val notes: List<MempoolNote>,
        val size: Int,
    ) : MempoolEvent
}

/** The net value an unconfirmed transaction moves for one account, in zatoshi. */
public data class MempoolAmount(
    val account: Int,
    val value: Long,
)

/** [memo] belongs to this note only — on a spend that is the memo of someone else's output. */
public data class MempoolNote(
    val account: Int,
    val value: Long,
    val pool: Pool,
    val memo: String?,
)
