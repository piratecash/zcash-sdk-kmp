package cash.p.zcash

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** One instance, tolerant by design: a field added on the Rust side must not break this build. */
internal val nativeJson: Json = Json { ignoreUnknownKeys = true }

@Serializable
internal data class AccountDto(
    val id: Int,
    val name: String,
    val birth: Int,
    val aindex: Int,
    val dindex: Int,
    val position: Int,
    val hidden: Boolean,
    val enabled: Boolean,
    @SerialName("internal") val isInternal: Boolean,
    val hw: Int,
    val height: Int,
    val time: Long,
    val balance: Long,
) {
    fun toAccountInfo(): AccountInfo = AccountInfo(
        id = id,
        name = name,
        birthHeight = birth,
        accountIndex = aindex,
        diversifierIndex = dindex,
        position = position,
        height = height,
        time = time,
        balance = balance,
        hidden = hidden,
        enabled = enabled,
        internal = isInternal,
        hardwareWallet = hw != 0,
    )
}

@Serializable
internal data class AddressesDto(
    val unified: String? = null,
    val sapling: String? = null,
    val orchard: String? = null,
    val transparent: String? = null,
    val diversifierIndex: Int,
) {
    fun toAddresses(): Addresses = Addresses(unified, sapling, orchard, transparent, diversifierIndex)
}

@Serializable
internal data class RecipientDto(
    val address: String,
    val amount: Long,
    val pools: Int? = null,
    val memo: String? = null,
)

/** ZSA fields are not exposed to Kotlin yet; rlz fills them from `Recipient::default()`. */
private fun Recipient.toDto(): RecipientDto = RecipientDto(
    address = address,
    amount = amount,
    pools = pools?.mask,
    memo = memo,
)

@Serializable
internal data class TxPlanInDto(
    val pool: Int,
    val amount: Long?,
    val assetName: String,
) {
    fun toPlanInput(): PlanInput = PlanInput(pool.toPool(), amount, assetName)
}

@Serializable
internal data class TxPlanOutDto(
    val pool: Int,
    val amount: Long,
    val address: String,
    val assetName: String,
) {
    fun toPlanOutput(): PlanOutput = PlanOutput(pool.toPool(), amount, address, assetName)
}

@Serializable
internal data class TxPlanDto(
    val height: Int,
    val inputs: List<TxPlanInDto>,
    val outputs: List<TxPlanOutDto>,
    val fee: Long,
    val canSign: Boolean,
    val canBroadcast: Boolean,
) {
    fun toTransactionPlan(): TransactionPlan = TransactionPlan(
        height = height,
        inputs = inputs.map(TxPlanInDto::toPlanInput),
        outputs = outputs.map(TxPlanOutDto::toPlanOutput),
        fee = fee,
        canSign = canSign,
        canBroadcast = canBroadcast,
    )
}

@Serializable
internal data class TransactionDto(
    val id: Int,
    val txid: String,
    val height: Int,
    val time: Long,
    val value: Long,
    val memo: String? = null,
    val fee: Long = 0,
    val totalReceived: Long = 0,
    val isChange: Boolean = false,
    val recipient: String? = null,
) {
    fun toTransaction(): Transaction = Transaction(
        id = id,
        txid = txid,
        height = height,
        time = time,
        value = value,
        memo = memo,
        fee = fee,
        totalReceived = totalReceived,
        isChange = isChange,
        recipient = recipient,
    )
}

internal fun parseAccounts(json: String): List<AccountInfo> =
    nativeJson.decodeFromString<List<AccountDto>>(json).map(AccountDto::toAccountInfo)

internal fun parseTransactions(json: String): List<Transaction> =
    nativeJson.decodeFromString<List<TransactionDto>>(json).map(TransactionDto::toTransaction)

internal fun parseAddresses(json: String): Addresses =
    nativeJson.decodeFromString<AddressesDto>(json).toAddresses()

internal fun encodeRecipients(recipients: List<Recipient>): String =
    nativeJson.encodeToString(recipients.map(Recipient::toDto))

internal fun parseTransactionPlan(json: String): TransactionPlan =
    nativeJson.decodeFromString<TxPlanDto>(json).toTransactionPlan()

/** The native layer returns available, locked, change, value per pool in [Pool] bit order. */
internal fun LongArray.toPoolBalance(): PoolBalance =
    PoolBalance(
        Pool.entries.associateWith { pool ->
            val base = pool.bit * BALANCE_FIELDS
            Balance(
                available = getOrElse(base) { 0L },
                locked = getOrElse(base + 1) { 0L },
                changePending = getOrElse(base + 2) { 0L },
                valuePending = getOrElse(base + 3) { 0L },
            )
        }
    )

private const val BALANCE_FIELDS = 4

/** [Pool.bit] is the wire index for a single pool (distinct from [PoolSet]'s bitmask). */
private fun Int.toPool(): Pool =
    checkNotNull(Pool.entries.firstOrNull { it.bit == this }) { "Unknown pool bit: $this" }

@Serializable
internal data class MigrationStatusDto(
    val phase: String,
    val sdNotesCount: Int,
    val nonSdNotesCount: Int,
    val ironwoodSdCount: Int,
) {
    fun toMigrationStatus(): MigrationStatus = MigrationStatus(
        phase = phase.toMigrationPhase(),
        standardNotes = sdNotesCount,
        nonStandardNotes = nonSdNotesCount,
        migratedNotes = ironwoodSdCount,
    )
}

@Serializable
internal data class MigrationStepDto(
    val event: String,
    val fee: Long,
    val txid: String? = null,
    val status: MigrationStatusDto,
) {
    fun toMigrationStep(): MigrationStep = MigrationStep(
        event = event.toMigrationEvent(),
        fee = fee,
        txid = txid,
        status = status.toMigrationStatus(),
    )
}

internal fun parseAddressKind(wire: String): ZcashAddressKind? = when (wire) {
    "transparent" -> ZcashAddressKind.TRANSPARENT
    "sapling" -> ZcashAddressKind.SAPLING
    "unified" -> ZcashAddressKind.UNIFIED
    "tex" -> ZcashAddressKind.TEX
    "invalid" -> null
    else -> throw ZcashException("Unknown address kind: $wire")
}

private fun String.toMigrationPhase(): MigrationPhase = when (this) {
    "splitting" -> MigrationPhase.SPLITTING
    "migrating" -> MigrationPhase.MIGRATING
    "complete" -> MigrationPhase.COMPLETE
    else -> throw ZcashException("Unknown migration phase: $this")
}

private fun String.toMigrationEvent(): MigrationEvent = when (this) {
    "splitComplete" -> MigrationEvent.SPLIT_COMPLETE
    "migrateComplete" -> MigrationEvent.MIGRATE_COMPLETE
    "complete" -> MigrationEvent.COMPLETE
    "nothingToDo" -> MigrationEvent.NOTHING_TO_DO
    else -> throw ZcashException("Unknown migration event: $this")
}

internal fun parseMigrationStatus(json: String): MigrationStatus =
    nativeJson.decodeFromString<MigrationStatusDto>(json).toMigrationStatus()

internal fun parseMigrationStep(json: String): MigrationStep =
    nativeJson.decodeFromString<MigrationStepDto>(json).toMigrationStep()

@Serializable
internal data class BroadcastResultDto(
    val errorCode: Int,
    val message: String,
)

internal fun parseBroadcastResult(json: String): BroadcastResult =
    nativeJson.decodeFromString<BroadcastResultDto>(json).let {
        BroadcastResult(errorCode = it.errorCode, message = it.message)
    }

@Serializable
internal data class MempoolAmountDto(
    val account: Int,
    val value: Long,
) {
    fun toMempoolAmount(): MempoolAmount = MempoolAmount(account, value)
}

@Serializable
internal data class MempoolNoteDto(
    val account: Int,
    val value: Long,
    val pool: Int,
    val memo: String? = null,
) {
    fun toMempoolNote(): MempoolNote = MempoolNote(account, value, pool.toPool(), memo)
}

/** Flat on purpose: `kind` is read as an ordinary field, never as a polymorphic discriminator. */
@Serializable
internal data class MempoolEventDto(
    val kind: String,
    val height: Int = 0,
    val txid: String = "",
    val amounts: List<MempoolAmountDto> = emptyList(),
    val notes: List<MempoolNoteDto> = emptyList(),
    val size: Int = 0,
    val error: String? = null,
)

/** `null` means the run ended on its own; an end caused by a failure throws instead. */
internal fun parseMempoolEvent(json: String): MempoolEvent? =
    nativeJson.decodeFromString<MempoolEventDto>(json).toMempoolEvent()

private fun MempoolEventDto.toMempoolEvent(): MempoolEvent? = when (kind) {
    "epoch" -> MempoolEvent.Epoch(height)
    "unconfirmed" -> MempoolEvent.Unconfirmed(
        txid = txid,
        amounts = amounts.map(MempoolAmountDto::toMempoolAmount),
        notes = notes.map(MempoolNoteDto::toMempoolNote),
        size = size,
    )
    "ended" -> {
        if (error != null) throw ZcashException(error)
        null
    }
    else -> throw ZcashException("Unknown mempool event: $kind")
}
