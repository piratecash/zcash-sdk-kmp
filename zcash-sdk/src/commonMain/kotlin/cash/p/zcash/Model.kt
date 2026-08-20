package cash.p.zcash

/** Per-pool balances of a single account, in zatoshi. */
public data class PoolBalance(private val byPool: Map<Pool, Long>) {

    public operator fun get(pool: Pool): Long = byPool[pool] ?: 0L

    public val total: Long get() = byPool.values.sum()

    public val shielded: Long get() = total - get(Pool.TRANSPARENT)
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
