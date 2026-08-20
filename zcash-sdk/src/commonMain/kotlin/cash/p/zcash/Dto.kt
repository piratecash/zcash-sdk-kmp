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
) {
    fun toTransaction(): Transaction = Transaction(
        id = id,
        txid = txid,
        height = height,
        time = time,
        value = value,
        memo = memo,
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

/** The native layer returns one balance per pool, in [Pool] bit order. */
internal fun LongArray.toPoolBalance(): PoolBalance =
    PoolBalance(Pool.entries.associateWith { getOrElse(it.bit) { 0L } })

/** [Pool.bit] is the wire index for a single pool (distinct from [PoolSet]'s bitmask). */
private fun Int.toPool(): Pool =
    checkNotNull(Pool.entries.firstOrNull { it.bit == this }) { "Unknown pool bit: $this" }
