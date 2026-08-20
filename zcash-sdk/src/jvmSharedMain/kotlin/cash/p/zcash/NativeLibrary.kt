package cash.p.zcash

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean

internal const val LIBRARY_NAME: String = "zcash_sdk_kmp"

/** Platform difference is only how the binary is found; the binding above it is shared. */
internal expect fun loadNativeLibrary(name: String)

internal object NativeLibrary {

    private val loaded = AtomicBoolean(false)
    private val mutex = Mutex()

    suspend fun ensureLoaded() {
        if (loaded.get()) return
        mutex.withLock {
            if (loaded.get()) return
            withContext(Dispatchers.IO) { loadNativeLibrary(LIBRARY_NAME) }
            loaded.set(true)
        }
    }
}
