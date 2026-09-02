package cash.p.zcash

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Process-wide setup. Everything else on the SDK is per wallet. */
public object ZcashSdk {

    private val initMutex = Mutex()

    /**
     * rlz keeps one global sync state and one global cancellation channel, so two syncs must
     * never overlap — not even across wallets.
     */
    internal val syncMutex: Mutex = Mutex()

    @Volatile
    private var initialized = false

    /**
     * Loads the native library and points it at [dataDir]. Calling it again is a no-op.
     *
     * [legacyParamsDir], if given, is an extra read-only source for Sapling params — e.g. an
     * existing ECC SDK install — checked before downloading them.
     */
    public suspend fun initialize(dataDir: String, legacyParamsDir: String? = null) {
        if (initialized) return
        initMutex.withLock {
            if (initialized) return
            NativeLibrary.ensureLoaded()
            withContext(Dispatchers.IO) {
                mapNativeError { ZcashJni.initDataDir(dataDir) }
                legacyParamsDir?.let { dir -> mapNativeError { ZcashJni.setLegacyParamsDir(dir) } }
            }
            initialized = true
        }
    }
}

/**
 * Derives the unified spending key for [accountIndex] of the wallet [phrase] describes.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet: nothing is read from or written to a
 * database. The key is returned to the caller and never kept by the SDK.
 *
 * [accountIndex] is a zip32 account index in `0..Int.MAX_VALUE`.
 *
 * [passphrase] is the BIP-39 passphrase (the "25th word") and must match the one the account
 * was restored with, otherwise the key belongs to a different wallet.
 */
public suspend fun ZcashSdk.deriveSpendingKey(
    phrase: String,
    network: ZcashNetwork,
    accountIndex: Int = 0,
    passphrase: String? = null,
): ByteArray {
    require(accountIndex >= 0) { "Account index must not be negative" }
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.deriveSpendingKey(network.coin, phrase, passphrase, accountIndex) }
    }
}

/**
 * Derives the account-level transparent extended private key (`m/44'/<coin>'/0'`) of the wallet
 * [phrase] describes — the one key that covers every transparent address of the account, in the
 * form another wallet imports.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet: nothing is read from or written to a
 * database. The key is returned to the caller and never kept by the SDK.
 *
 * [passphrase] is the BIP-39 passphrase (the "25th word") and must match the one the account
 * was restored with, otherwise the key belongs to a different wallet.
 */
public suspend fun ZcashSdk.deriveTransparentAccountKey(
    phrase: String,
    network: ZcashNetwork,
    passphrase: String? = null,
): String {
    require(phrase.isNotBlank()) { "Phrase must not be blank" }
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.deriveTransparentAccountKey(network.coin, phrase, passphrase) }
    }
}

/**
 * Derives the unified full viewing key of account 0 of the wallet [phrase] describes — the
 * watch-only key that sees every pool of the account and holds no spending material.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet: nothing is read from or written to a
 * database. The key is returned to the caller and never kept by the SDK.
 *
 * [passphrase] is the BIP-39 passphrase (the "25th word") and must match the one the account
 * was restored with, otherwise the key belongs to a different wallet.
 */
public suspend fun ZcashSdk.deriveUfvk(
    phrase: String,
    network: ZcashNetwork,
    passphrase: String? = null,
): String {
    require(phrase.isNotBlank()) { "Phrase must not be blank" }
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.deriveUfvk(network.coin, phrase, passphrase) }
    }
}

/**
 * The Sapling viewing key for [spendingKey] on [network], or `null` when it is not a Sapling
 * extended spending key there.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet: the derivation is offline and stateless,
 * nothing is read from or written to a database.
 */
public suspend fun ZcashSdk.deriveSaplingViewingKey(
    spendingKey: String,
    network: ZcashNetwork,
): String? {
    if (spendingKey.isBlank()) return null
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.deriveSaplingViewingKey(network.coin, spendingKey) }
    }
}

/**
 * Every address of [accountIndex] for the wallet [phrase] describes.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet, so a receive screen can show an address
 * before the wallet is opened. The result matches [ZcashWallet.addresses] of an account
 * restored from the same phrase, index and passphrase.
 */
public suspend fun ZcashSdk.deriveAddresses(
    phrase: String,
    network: ZcashNetwork,
    accountIndex: Int = 0,
    passphrase: String? = null,
): Addresses {
    require(accountIndex >= 0) { "Account index must not be negative" }
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError {
            parseAddresses(
                ZcashJni.deriveAddresses(network.coin, phrase, passphrase, accountIndex)
            )
        }
    }
}

/**
 * [deriveAddresses] for a watch-only wallet: every address the unified full viewing key
 * [viewingKey] yields, without a database.
 */
public suspend fun ZcashSdk.deriveAddressesFromViewingKey(
    viewingKey: String,
    network: ZcashNetwork,
): Addresses {
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { parseAddresses(ZcashJni.addressesFromViewingKey(network.coin, viewingKey)) }
    }
}

/**
 * The component mask [key] encodes on [network] — transparent, Sapling, Orchard — as a
 * bitwise-OR of [Pool] bits. This reflects what the key *contains*, not what it can spend from:
 * a transparent receiver address contains no key material at all and yields [PoolSet.NONE], and
 * so does anything [ZcashSdk] does not recognize. [Pool.IRONWOOD] never appears in the result:
 * authority over Ironwood follows Orchard, so a key carrying Orchard carries Ironwood too.
 *
 * The very first call blocks while the native library loads, unless [ZcashSdk.initialize] or any
 * other SDK call already did it.
 */
public fun ZcashSdk.keyPools(key: String, network: ZcashNetwork): PoolSet {
    NativeLibrary.ensureLoadedBlocking()
    return mapNativeError { PoolSet(ZcashJni.keyPools(network.coin, key)) }
}

/**
 * Whether [keyPools] classifies [key] on [network]. Narrower than what
 * [ZcashWallet.restoreAccount] parses: a single-address transparent secret (WIF, `zpk`) restores
 * but is not classified here, and neither is a receiver address.
 */
public fun ZcashSdk.isValidKey(key: String, network: ZcashNetwork): Boolean =
    keyPools(key, network) != PoolSet.NONE

/**
 * [deriveAddresses] and [deriveAddressesFromViewingKey] generalized to every key format
 * [keyPools] classifies. Only the pools [key] itself carries are populated; every other field of
 * [Addresses] is `null`. Throws on anything else, so gate the call on [isValidKey].
 */
public suspend fun ZcashSdk.deriveAddressesFromKey(key: String, network: ZcashNetwork): Addresses {
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { parseAddresses(ZcashJni.addressesFromKey(network.coin, key)) }
    }
}

/**
 * Whether [ZcashWallet.restoreAccount] would import [key] as a spending key rather than
 * watch-only.
 *
 * A mnemonic phrase also spends, but through [ZcashWallet.restoreAccount] itself and
 * [ZcashSdk.deriveSpendingKey] — this predicate names a narrower thing, the set of standalone
 * key formats accepted as spending material — so it returns `false` for a phrase.
 */
public fun ZcashSdk.isSpendingKey(key: String, network: ZcashNetwork): Boolean {
    NativeLibrary.ensureLoadedBlocking()
    return mapNativeError { ZcashJni.isSpendingKey(network.coin, key) }
}

/**
 * The signing envelope for a standalone spending [key], in the form [ZcashWallet.sign]
 * takes.
 *
 * Accepts exactly the formats [isSpendingKey] reports and throws on anything else, so gate the
 * call on that predicate. Needs no [ZcashSdk.initialize] and no open wallet, and stores nothing —
 * the returned bytes are the caller's to hold and to clear.
 */
public fun ZcashSdk.importSpendingKey(key: String, network: ZcashNetwork): ByteArray {
    NativeLibrary.ensureLoadedBlocking()
    return mapNativeError { ZcashJni.importSpendingKey(network.coin, key) }
}

/**
 * The kind of [address] on [network], or `null` when it is not a valid address there.
 *
 * Decoding checks the checksum and the network prefix, reads no database and makes no network
 * call — hence a plain function. Keeping it synchronous is deliberate: a caller gating a button
 * on the result cannot race a stale answer against newer input.
 *
 * The very first call blocks while the native library loads, unless [ZcashSdk.initialize] or any
 * other SDK call already did it.
 */
public fun ZcashSdk.addressKind(address: String, network: ZcashNetwork): ZcashAddressKind? {
    NativeLibrary.ensureLoadedBlocking()
    return mapNativeError { parseAddressKind(ZcashJni.addressKind(network.coin, address)) }
}

/**
 * Which receiver kinds [address] carries on [network]. Unlike [addressKind], which only names
 * the address's own format, this looks inside a unified address for what it actually holds —
 * e.g. whether it carries a transparent (ZIP-320 TEX-capable) receiver.
 *
 * The very first call blocks while the native library loads, unless [ZcashSdk.initialize] or any
 * other SDK call already did it.
 */
public fun ZcashSdk.addressReceivers(address: String, network: ZcashNetwork): AddressReceivers {
    require(address.isNotBlank()) { "Address must not be blank" }
    NativeLibrary.ensureLoadedBlocking()
    return mapNativeError { parseAddressReceivers(ZcashJni.addressReceivers(network.coin, address)) }
}

/**
 * The txid of a fully signed transaction, in the display order explorers use.
 *
 * Needs no [ZcashSdk.initialize] and no open wallet: the bytes carry everything. An offline
 * signer needs this, because otherwise only [ZcashWallet.broadcast] reports a txid.
 */
public suspend fun ZcashSdk.transactionId(rawTransaction: ByteArray): String {
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.transactionId(rawTransaction) }
    }
}

/**
 * A fresh BIP-39 seed phrase. Needs no [ZcashSdk.initialize].
 *
 * The SDK does not keep it: storing the phrase and restoring an account from it are the
 * caller's job.
 */
public suspend fun ZcashSdk.generateSeedPhrase(): String {
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) { mapNativeError { ZcashJni.generateSeedPhrase() } }
}

/** The native side throws `RuntimeException`; callers of this SDK see [ZcashException]. */
internal inline fun <T> mapNativeError(block: () -> T): T =
    try {
        block()
    } catch (e: RuntimeException) {
        throw ZcashException(e.message ?: "Native call failed", e)
    }
