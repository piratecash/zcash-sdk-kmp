package cash.p.zcash

import java.io.File
import java.nio.file.Files
import java.util.Locale

/** Desktop has no packaged JNI dir, so the binary is unpacked from the jar on first use. */
internal actual fun loadNativeLibrary(name: String) {
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
