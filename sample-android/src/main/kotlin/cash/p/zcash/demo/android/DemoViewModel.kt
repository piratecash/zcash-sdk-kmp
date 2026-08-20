package cash.p.zcash.demo.android

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import cash.p.zcash.demo.DemoController

/**
 * The controller outlives Activity re-creation on purpose: a native scan keeps running after the
 * Activity dies, so a controller tied to `lifecycleScope` would lose the collector and open a
 * second wallet handle on every rotation.
 *
 * Nothing is closed in `onCleared()`: `ZcashWallet.close()` is suspending, `viewModelScope` is
 * already cancelled by then, and the SDK's connection pool lives until the process ends anyway.
 */
internal class DemoViewModel(dataDir: String) : ViewModel() {

    val controller: DemoController = DemoController(dataDir, viewModelScope)

    init {
        controller.start()
    }
}
