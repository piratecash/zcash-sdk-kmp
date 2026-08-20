package cash.p.zcash

/**
 * The single JNI binding. Android and desktop are both JVM targets, so neither a C ABI
 * nor a second wrapper is needed.
 *
 * A wallet is addressed by the opaque handle [open] returns; `0` is never a valid handle.
 * Every function throws on native failure, so nothing here reports errors in-band.
 */
internal object ZcashJni {

    external fun initDataDir(directory: String)

    external fun open(
        dbPath: String,
        dbKey: ByteArray?,
        coin: Byte,
        url: String,
        serverType: Byte,
        transport: Byte,
        proxy: String,
    ): Long

    external fun close(handle: Long)

    external fun newAccount(
        handle: Long,
        name: String,
        key: String,
        birthHeight: Int,
        pools: Int,
        accountIndex: Int,
    ): Int

    external fun listAccounts(handle: Long): String

    external fun deleteAccount(handle: Long, account: Int)

    external fun setAccount(handle: Long, account: Int)

    external fun accountAddresses(handle: Long, account: Int): String

    external fun balance(handle: Long, account: Int): LongArray

    external fun listTransactions(handle: Long, account: Int): String

    external fun synchronize(
        handle: Long,
        accounts: IntArray,
        currentHeight: Int,
        actionsPerSync: Int,
        transparentLimit: Int,
        checkpointAge: Int,
        noskipDetails: Boolean,
    )

    external fun cancelSync()

    /** Packed `(height, time)` of the last reported block; `0` before the first one. */
    external fun syncProgress(): Long

    external fun latestHeight(handle: Long): Int

    /** A read-only extra source for Sapling params, e.g. an existing ECC SDK install. */
    external fun setLegacyParamsDir(directory: String)

    external fun prepare(
        handle: Long,
        account: Int,
        recipientsJson: String,
        srcPools: Byte,
        recipientPaysFee: Boolean,
        smartTransparent: Boolean,
    ): ByteArray

    external fun transactionPlan(handle: Long, pkg: ByteArray): String

    external fun signTransaction(
        handle: Long,
        account: Int,
        pkg: ByteArray,
        spendingKey: ByteArray,
    ): ByteArray

    /** Stateless: needs no open wallet. */
    external fun deriveSpendingKey(coin: Byte, phrase: String, accountIndex: Int): ByteArray

    /** Stateless: needs no open wallet. */
    external fun generateSeedPhrase(): String

    external fun extractTransaction(pkg: ByteArray): ByteArray

    external fun broadcastTransaction(handle: Long, height: Int, tx: ByteArray): String
}
