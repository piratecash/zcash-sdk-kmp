package cash.p.zcash

import kotlinx.serialization.Serializable

/**
 * One pool's unspent value in zatoshi, split by whether it can be spent yet.
 *
 * [changePending] is change coming back from own spends, [valuePending] is incoming payments.
 */
public data class Balance(
    val available: Long = 0L,
    val changePending: Long = 0L,
    val valuePending: Long = 0L,
    val locked: Long = 0L,
) {
    public val pending: Long get() = changePending + valuePending

    public val total: Long get() = available + locked + pending
}

/** Per-pool balances of a single account, in zatoshi. */
public data class PoolBalance(private val byPool: Map<Pool, Balance>) {

    public operator fun get(pool: Pool): Balance = byPool[pool] ?: Balance()

    public val available: Long get() = byPool.values.sumOf { it.available }

    public val locked: Long get() = byPool.values.sumOf { it.locked }

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

/** Which receiver kinds a (possibly unified) address carries. */
public data class AddressReceivers(val hasTransparent: Boolean)

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
    val confirmations: Int = DEFAULT_CONFIRMATIONS,
    /** Forces a v5 (ZIP-244) transaction so an external hardware signer (e.g. Trezor) can sign it. */
    val hardwareSigning: Boolean = false,
    /**
     * Plans for a device that signs the PCZT field by field (e.g. Ledger): no Sapling, within the
     * device's limits, and the branch's own transaction version. A plan the device cannot sign
     * fails with [ZcashException.externalSigningRefusal] set.
     */
    val externalPcztSigning: Boolean = false,
) {
    init {
        require(confirmations >= 0) { "Confirmations must not be negative: $confirmations" }
        require(!(hardwareSigning && externalPcztSigning)) {
            "hardwareSigning and externalPcztSigning target different signers"
        }
    }
}

public const val DEFAULT_CONFIRMATIONS: Int = 10

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
 * The JSON payload an external signer (e.g. Trezor) needs to review and sign a PCZT's
 * transparent bundle. Returned by [ZcashWallet.transparentSigningRequest].
 */
public data class TransparentSigningRequest(
    val txVersion: Int,
    val versionGroupId: Long,
    val consensusBranchId: Long,
    val expiryHeight: Int,
    val lockTime: Long,
    val shielded: ShieldedCounts,
    val inputs: List<TransparentSigningInput>,
    val outputs: List<TransparentSigningOutput>,
)

/** Shielded component counts, so the caller can refuse a bundle the device cannot sign. */
public data class ShieldedCounts(
    val saplingSpends: Int,
    val saplingOutputs: Int,
    val orchardActions: Int,
)

/** One transparent input of a [TransparentSigningRequest]. */
public data class TransparentSigningInput(
    val index: Int,
    val prevTxid: String,
    val prevIndex: Int,
    val value: Long,
    val sequence: Long,
    val scope: Int,
    val dindex: Int,
    val scriptPubkey: String,
)

/** One transparent output of a [TransparentSigningRequest]. [scope]/[dindex] are set only for change. */
public data class TransparentSigningOutput(
    val index: Int,
    val value: Long,
    val address: String,
    val isChange: Boolean,
    val scope: Int? = null,
    val dindex: Int? = null,
)

/**
 * What a device that signs a PCZT field by field (e.g. Ledger) needs, from
 * [ZcashWallet.externalSigningView]. Byte fields are hex; paths hold raw BIP-32/ZIP-32 indices
 * with the hardened bit (`0x8000_0000`) set.
 */
public data class ExternalSigningView(
    val txVersion: Int,
    val versionGroupId: Long,
    val consensusBranchId: Long,
    val fallbackLockTime: Long?,
    val expiryHeight: Int,
    val coinType: Int,
    val txModifiable: Int,
    val transparentInputs: List<ExternalTransparentInput>,
    val transparentOutputs: List<ExternalTransparentOutput>,
    val orchard: ExternalActionBundle?,
    /** Always null below transaction version 6. */
    val ironwood: ExternalActionBundle?,
)

public data class ExternalKeyDerivation(val pubkey: String, val seedFingerprint: String, val path: List<Long>)

public data class ExternalTransparentInput(
    val prevoutTxid: String,
    val prevoutIndex: Int,
    val sequence: Long?,
    val value: Long,
    val scriptPubkey: String,
    val sighashType: Int,
    val derivation: ExternalKeyDerivation,
)

/** [derivation] is set only on the wallet's own change output. */
public data class ExternalTransparentOutput(
    val value: Long,
    val scriptPubkey: String,
    val derivation: ExternalKeyDerivation?,
)

/** [signIndices] are the actions the device signs; the others are dummies the host signed already. */
public data class ExternalActionBundle(
    val actions: List<ExternalAction>,
    val flags: Int,
    /** Spends minus outputs, in zatoshi. */
    val valueBalance: Long,
    val anchor: String,
    val notePlaintextVersion: Int,
    val signIndices: List<Int>,
)

/** [recipientAddress] is the Orchard-only unified address the device shows for this output. */
public data class ExternalAction(
    val cvNet: String,
    val nullifier: String,
    val rk: String,
    val spendRecipient: String,
    val spendValue: Long,
    val spendRho: String,
    val spendRseed: String,
    val alpha: String,
    val seedFingerprint: String,
    val path: List<Long>,
    val cmx: String,
    val ephemeralKey: String,
    val encCiphertext: String,
    val outCiphertext: String,
    val recipient: String,
    val recipientAddress: String,
    val value: Long,
    val rseed: String,
    val rcv: String,
)

/**
 * A device's answers keyed by index: 64-byte spend authorization signatures per Orchard/Ironwood
 * action, and DER ‖ sighash type per transparent input, exactly as the device returns them.
 */
public class ExternalSignatures(
    public val orchard: Map<Int, ByteArray>,
    public val ironwood: Map<Int, ByteArray>,
    public val transparent: Map<Int, ByteArray>,
)

/** Why the external device cannot sign a payment; see [ZcashException.externalSigningRefusal]. */
public enum class ExternalSigningRefusal(internal val code: String) {
    SAPLING("sapling"),
    SHIELDED_RECIPIENTS("shielded-recipients"),
    TRANSPARENT_INPUTS("transparent-inputs"),
    TRANSPARENT_OUTPUTS("transparent-outputs"),
    ORCHARD_ACTIONS("orchard-actions"),
    IRONWOOD_ACTIONS("ironwood-actions"),
}

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

/**
 * Process-wide diagnostics of the SDK's native database opens. [cantOpenFailures] and
 * [recoveredByRetry] count acquire attempts; [nativeCantOpen] counts SQLite's own reports (one
 * failure can emit two), so compare it by growth. [recent] is SQLite's log, paths and SQL removed.
 */
public data class DatabaseStats(
    public val opens: Long,
    public val nativeCantOpen: Long,
    public val cantOpenFailures: Long,
    public val recoveredByRetry: Long,
    public val lastError: String?,
    public val recent: List<String>,
    public val pools: List<DatabasePool> = emptyList(),
    public val lastSeq: Long = 0,
)

/** One connection pool's current footprint, as the native side samples it. */
public data class DatabasePool(
    public val id: Long,
    public val path: String,
    public val size: Int,
    public val idle: Int,
)

@Serializable
internal data class DatabaseStatsDto(
    val opens: Long,
    val nativeCantopen: Long,
    val cantopenFailures: Long,
    val recoveredByRetry: Long,
    val lastError: String? = null,
    val recent: List<String> = emptyList(),
    val lastSeq: Long = 0,
    val pools: List<DatabasePoolDto> = emptyList(),
) {
    fun toDatabaseStats(): DatabaseStats =
        DatabaseStats(
            opens,
            nativeCantopen,
            cantopenFailures,
            recoveredByRetry,
            lastError,
            recent,
            pools.map { it.toDatabasePool() },
            lastSeq,
        )
}

@Serializable
internal data class DatabasePoolDto(
    val id: Long,
    val path: String,
    val size: Int,
    val idle: Int,
) {
    fun toDatabasePool(): DatabasePool = DatabasePool(id, path, size, idle)
}

internal fun parseDatabaseStats(json: String): DatabaseStats =
    nativeJson.decodeFromString<DatabaseStatsDto>(json).toDatabaseStats()

/**
 * Process-wide: [streamBreaks] counts every failure of a sync's compact-block stream, a failed
 * reopen included; [streamResumed] counts reopens that then delivered a block.
 */
public data class NetworkStats(
    public val streamBreaks: Long,
    public val streamResumed: Long,
)

@Serializable
internal data class NetworkStatsDto(
    val streamBreaks: Long,
    val streamResumed: Long,
) {
    fun toNetworkStats(): NetworkStats = NetworkStats(streamBreaks, streamResumed)
}

internal fun parseNetworkStats(json: String): NetworkStats =
    nativeJson.decodeFromString<NetworkStatsDto>(json).toNetworkStats()

/**
 * One measurement of a mainnet lightwalletd server. [infoMs] covers a fresh connect plus
 * `GetLightdInfo`; [rangeMs] the block range that ends at [blockHeight].
 */
public data class ServerProbe(
    public val chainName: String,
    public val saplingActivationHeight: Int,
    public val consensusBranchId: String,
    public val blockHeight: Int,
    public val estimatedHeight: Int,
    /** The server's branch id is the one mainnet has at [blockHeight]. */
    public val branchIdMatches: Boolean,
    public val infoMs: Long,
    public val rangeMs: Long,
    public val rangeBlocksReceived: Int,
)

@Serializable
internal data class ServerProbeDto(
    val chainName: String,
    val saplingActivationHeight: Int,
    val consensusBranchId: String,
    val blockHeight: Int,
    val estimatedHeight: Int,
    val branchIdMatches: Boolean,
    val infoMs: Long,
    val rangeMs: Long,
    val rangeBlocksReceived: Int,
) {
    fun toServerProbe(): ServerProbe = ServerProbe(
        chainName = chainName,
        saplingActivationHeight = saplingActivationHeight,
        consensusBranchId = consensusBranchId,
        blockHeight = blockHeight,
        estimatedHeight = estimatedHeight,
        branchIdMatches = branchIdMatches,
        infoMs = infoMs,
        rangeMs = rangeMs,
        rangeBlocksReceived = rangeBlocksReceived,
    )
}

internal fun parseServerProbe(json: String): ServerProbe =
    nativeJson.decodeFromString<ServerProbeDto>(json).toServerProbe()
