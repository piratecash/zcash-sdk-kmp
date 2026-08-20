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
 */
public suspend fun ZcashSdk.deriveSpendingKey(
    phrase: String,
    network: ZcashNetwork,
    accountIndex: Int = 0,
): ByteArray {
    require(accountIndex >= 0) { "Account index must not be negative" }
    NativeLibrary.ensureLoaded()
    return withContext(Dispatchers.IO) {
        mapNativeError { ZcashJni.deriveSpendingKey(network.coin, phrase, accountIndex) }
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
