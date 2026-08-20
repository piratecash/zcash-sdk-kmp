package cash.p.zcash.demo.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.viewmodel.compose.viewModel
import cash.p.zcash.demo.DemoApp

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val dataDir = filesDir.absolutePath
        setContent {
            val demoViewModel: DemoViewModel = viewModel { DemoViewModel(dataDir) }
            DemoApp(demoViewModel.controller)
        }
    }
}
