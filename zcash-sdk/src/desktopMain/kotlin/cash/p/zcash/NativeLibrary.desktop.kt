package cash.p.zcash

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale

/** Where a packaged desktop application keeps the native; see [NATIVE_DIR_PROPERTY]. */
public object ZcashNativeLibrary {
    /** Directory to load the native from, with no extraction and no fallback to the jar copy. */
    public const val NATIVE_DIR_PROPERTY: String = "zcash.sdk.native.dir"
}

/**
 * Desktop has no packaged JNI dir, so the binary is unpacked from the jar on first use,
 * unless [ZcashNativeLibrary.NATIVE_DIR_PROPERTY] names the directory to load it from.
 */
internal actual fun loadNativeLibrary(name: String) {
    loadNativeLibraryFrom(name, System.getProperty(ZcashNativeLibrary.NATIVE_DIR_PROPERTY))
}

internal fun loadNativeLibraryFrom(name: String, nativeDir: String?) {
    if (nativeDir == null) loadFromJar(name) else loadFromDir(name, nativeDir)
}

// The file belongs to the installed, OS-signed app, which may re-sign it.
private fun loadFromDir(name: String, nativeDir: String) {
    val library = Path.of(nativeDir).resolve(System.mapLibraryName(name))
    require(Files.isRegularFile(library)) { "Zcash native is missing: $library" }
    System.load(library.toAbsolutePath().toString())
}

private fun loadFromJar(name: String) {
    val fileName = System.mapLibraryName(name)
    val resourcePath = "/native/$hostTriple/$fileName"
    val source = NativeLibrary::class.java.getResourceAsStream(resourcePath)
        ?: error("Native library not found in resources: $resourcePath")

    val target = File(Files.createTempDirectory("zcash-sdk").toFile(), fileName)
    target.deleteOnExit()
    source.use { input -> target.outputStream().use(input::copyTo) }

    System.load(target.absolutePath)
}

private val hostTriple: String
    get() {
        val os = System.getProperty("os.name").lowercase(Locale.ROOT)
        val arch = when (val raw = System.getProperty("os.arch").lowercase(Locale.ROOT)) {
            "amd64", "x86_64" -> "x86_64"
            "aarch64", "arm64" -> "aarch64"
            else -> error("Unsupported architecture: $raw")
        }
        return when {
            os.startsWith("mac") -> "$arch-apple-darwin"
            os.startsWith("windows") -> "$arch-pc-windows-msvc"
            os.startsWith("linux") -> "$arch-unknown-linux-gnu"
            else -> error("Unsupported OS: $os")
        }
    }
