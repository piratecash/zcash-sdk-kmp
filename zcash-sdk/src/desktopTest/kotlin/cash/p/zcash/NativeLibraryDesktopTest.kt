package cash.p.zcash

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NativeLibraryDesktopTest {

    @Test
    fun loadNativeLibraryFrom_nativeDirWithoutLibrary_failsNamingThePathWithoutExtracting() {
        val nativeDir = Files.createTempDirectory("zcash-native-dir")
        val expected = nativeDir.resolve(System.mapLibraryName(LIBRARY_NAME)).toString()
        val extractedBefore = extractedCopies()

        val error = assertFailsWith<IllegalArgumentException> {
            loadNativeLibraryFrom(LIBRARY_NAME, nativeDir.toString())
        }

        assertTrue(error.message.orEmpty().contains(expected))
        assertEquals(extractedBefore, extractedCopies())
    }

    private fun extractedCopies(): Set<String> =
        File(System.getProperty("java.io.tmpdir")).list { _, name -> name.startsWith("zcash-sdk") }.orEmpty().toSet()
}
