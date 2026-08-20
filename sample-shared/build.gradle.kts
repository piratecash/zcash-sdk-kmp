import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

// The seed never reaches the repository: it is read from local.properties at build time and
// baked into a generated object, so the demo has no seed-entry screen and no runtime storage.
val generateDemoConfig = tasks.register<GenerateDemoConfig>("generateDemoConfig") {
    localProperties.from(rootProject.layout.projectDirectory.file("local.properties"))
    outputDirectory.set(layout.buildDirectory.dir("generated/demo"))
}

kotlin {
    androidLibrary {
        namespace = "cash.p.zcash.demo"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()

        // Compose resources reach the APK through the variant's assets, which the KMP
        // Android plugin leaves disabled by default.
        androidResources.enable = true

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    jvm("desktop") {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(generateDemoConfig)

            dependencies {
                api(project(":zcash-sdk"))
                implementation(libs.compose.multiplatform.runtime)
                implementation(libs.compose.multiplatform.foundation)
                implementation(libs.compose.multiplatform.material3)
                implementation(libs.compose.multiplatform.resources)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
            }
        }
    }
}

compose.resources {
    publicResClass = false
    packageOfResClass = "cash.p.zcash.demo.resources"
}

@CacheableTask
abstract class GenerateDemoConfig : DefaultTask() {

    // A file collection, not an InputFile: local.properties is absent on a fresh checkout and an
    // absent InputFile fails validation instead of generating an empty config.
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val localProperties: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @TaskAction
    fun generate() {
        val properties = Properties()
        localProperties.files.filter { it.isFile }.forEach { file ->
            file.inputStream().use { properties.load(it) }
        }
        val words = properties.getProperty("zcash.words").orEmpty()
        val dbKey = properties.getProperty("zcash.dbKey").orEmpty().trim()
        // The SDK takes a raw 32-byte SQLCipher key and derives nothing, so a missing key would
        // silently open the wallet unencrypted. Required whenever there is a wallet to open.
        if (words.isNotBlank() && !dbKey.matches(Regex("[0-9a-fA-F]{64}"))) {
            throw GradleException(
                "zcash.dbKey is missing or malformed in local.properties. It is required " +
                    "whenever zcash.words is set, and must be 64 hex characters (a raw " +
                    "32-byte key, not a passphrase). Generate one with: openssl rand -hex 32"
            )
        }
        val birthday = properties.getProperty("zcash.birthday")?.toIntOrNull() ?: 0
        val serverUrl = properties.getProperty("zcash.serverUrl")
            ?: "https://zec.rocks:443"

        val directory = outputDirectory.get().asFile.resolve("cash/p/zcash/demo")
        directory.mkdirs()
        directory.resolve("DemoConfig.kt").writeText(
            """
            package cash.p.zcash.demo

            internal object DemoConfig {
                const val WORDS: String = "$words"
                const val DB_KEY: String = "$dbKey"
                const val BIRTHDAY: Int = $birthday
                const val SERVER_URL: String = "$serverUrl"
            }

            """.trimIndent()
        )
    }
}
