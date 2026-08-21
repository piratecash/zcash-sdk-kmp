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
