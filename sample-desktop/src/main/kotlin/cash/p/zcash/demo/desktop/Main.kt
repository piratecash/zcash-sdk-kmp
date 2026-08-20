package cash.p.zcash.demo.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import cash.p.zcash.demo.DemoApp
import cash.p.zcash.demo.DemoController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import java.io.File

fun main() {
    val dataDir = File(System.getProperty("user.home"), ".zcash-sdk-demo").apply { mkdirs() }
    val controller = DemoController(dataDir.absolutePath, CoroutineScope(SupervisorJob() + Dispatchers.Main))
    controller.start()

    application {
        Window(onCloseRequest = ::exitApplication, title = "Zcash SDK demo") {
            DemoApp(controller)
        }
    }
}
