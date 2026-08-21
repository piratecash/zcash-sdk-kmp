package cash.p.zcash

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

internal const val LIBRARY_NAME: String = "zcash_sdk_kmp"

/** Platform difference is only how the binary is found; the binding above it is shared. */
internal expect fun loadNativeLibrary(name: String)

internal object NativeLibrary {

    private val library: Lazy<Unit> = lazy { loadNativeLibrary(LIBRARY_NAME) }

    /** Blocks the caller while the binary loads, so a synchronous API can use it too. */
    fun ensureLoadedBlocking() {
        library.value
    }

    suspend fun ensureLoaded() {
        if (library.isInitialized()) return
        withContext(Dispatchers.IO) { ensureLoadedBlocking() }
    }
}
