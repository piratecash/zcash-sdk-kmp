package cash.p.zcash

internal actual fun loadNativeLibrary(name: String) {
    System.loadLibrary(name)
}
