import cash.p.zcash.gradle.CargoHostTask
import cash.p.zcash.gradle.CargoNdkTask
import com.android.build.api.variant.KotlinMultiplatformAndroidComponentsExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kmp.library)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------
//
// Values are resolved eagerly: providers are tracked as configuration-cache inputs either
// way, and a lambda here would capture the build script object, which the cache cannot
// serialize.

val rustWorkspace = rootProject.layout.projectDirectory.dir("rust")

val releaseProfile = providers.gradleProperty("zcashSdk.rustRelease").orNull.toBoolean()
val cargoProfile = if (releaseProfile) "release" else "dev"
val cargoProfileDirectory = if (releaseProfile) "release" else "debug"

val cargoExecutable = providers.environmentVariable("CARGO")
    .orElse(providers.systemProperty("user.home").map { "$it/.cargo/bin/cargo" })
    .get()

val androidAbis = providers.gradleProperty("zcashSdk.androidAbis").get().split(',').map(String::trim)

val prebuiltDesktop = layout.projectDirectory.dir("prebuilt/desktop")
val prebuiltAndroidNatives = layout.projectDirectory.dir("prebuilt/android/native")
val usesPrebuiltDesktop = prebuiltDesktop.dir("native").asFile.isDirectory
val usesPrebuiltAndroid = prebuiltAndroidNatives.asFile.isDirectory

if (usesPrebuiltAndroid) {
    val missingAbis = androidAbis.filter { abi ->
        val library = prebuiltAndroidNatives.file("$abi/libzcash_sdk_kmp.so").asFile
        !library.isFile || library.length() == 0L
    }
    if (missingAbis.isNotEmpty()) {
        error(
            "Incomplete prebuilt Android natives for: ${missingAbis.joinToString()}. " +
                "Delete zcash-sdk/prebuilt/android and rebuild them with cargo-ndk."
        )
    }
}

val osName = providers.systemProperty("os.name").get()
val isMac = osName.startsWith("Mac", ignoreCase = true)
val isWindows = osName.startsWith("Windows", ignoreCase = true)

val hostCpu = when (val arch = providers.systemProperty("os.arch").get().lowercase()) {
    "amd64", "x86_64" -> "x86_64"
    "aarch64", "arm64" -> "aarch64"
    else -> error("Unsupported architecture: $arch")
}
val hostTargetTriple = when {
    isMac -> "$hostCpu-apple-darwin"
    isWindows -> "$hostCpu-pc-windows-msvc"
    else -> "$hostCpu-unknown-linux-gnu"
}
val hostLibraryName = when {
    isMac -> "libzcash_sdk_kmp.dylib"
    isWindows -> "zcash_sdk_kmp.dll"
    else -> "libzcash_sdk_kmp.so"
}

// `target/` holds hundreds of megabytes of build output; only real sources are inputs.
val rustSourceFiles = fileTree(rustWorkspace) {
    include("**/*.rs", "**/Cargo.toml", "**/Cargo.lock", "**/build.rs")
    exclude("target/**")
}

val cargoBuildAndroid = if (usesPrebuiltAndroid) {
    null
} else {
    val ndkDirectory = providers.environmentVariable("ANDROID_NDK_HOME").orNull
        ?: providers.environmentVariable("ANDROID_HOME").orNull?.let {
            "$it/ndk/${providers.gradleProperty("zcashSdk.ndkVersion").get()}"
        }
        ?: error("Set ANDROID_NDK_HOME or ANDROID_HOME to cross-compile the Rust bridge")

    tasks.register<CargoNdkTask>("cargoBuildAndroid") {
        description = "Cross-compiles the Rust JNI bridge for the configured Android ABIs."
        rustSources.from(rustSourceFiles)
        cargoBinary.set(cargoExecutable)
        // `ndk` is a cargo subcommand; everything after `--` is forwarded to cargo itself.
        arguments.set(
            listOf("ndk") + androidAbis.flatMap { listOf("-t", it) } +
                listOf("-P", libs.versions.minSdk.get(), "--", "build", "-p", "zcash-jni", "--profile", cargoProfile)
        )
        libraryName.set("libzcash_sdk_kmp.so")
        cargoEnvironment.set(mapOf("ANDROID_NDK_HOME" to ndkDirectory))
        workspace.set(rustWorkspace)
        outputDirectory.set(layout.buildDirectory.dir("rust/jniLibs"))
    }
}

val cargoBuildDesktop = if (usesPrebuiltDesktop) {
    null
} else {
    tasks.register<CargoHostTask>("cargoBuildDesktop") {
        description = "Builds the Rust JNI bridge for the host and stages it as desktop resources."
        rustSources.from(rustSourceFiles)
        cargoBinary.set(cargoExecutable)
        arguments.set(listOf("build", "-p", "zcash-jni", "--profile", cargoProfile))
        cargoEnvironment.set(emptyMap<String, String>())
        workspace.set(rustWorkspace)
        hostTriple.set(hostTargetTriple)
        binary.set(rustWorkspace.file("target/$cargoProfileDirectory/$hostLibraryName"))
        outputDirectory.set(layout.buildDirectory.dir("rust/desktopResources"))
    }
}

// ---------------------------------------------------------------------------
// Kotlin
// ---------------------------------------------------------------------------

kotlin {
    android {
        namespace = "cash.p.zcash"
        compileSdk = libs.versions.compileSdk.get().toInt()
        minSdk = libs.versions.minSdk.get().toInt()

        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }

        withHostTest { }
    }

    jvm("desktop") {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_21)
        }
    }

    applyDefaultHierarchyTemplate()

    sourceSets {
        // Both targets are JVM, so a single JNI binding serves Android and desktop.
        val jvmSharedMain by creating {
            dependsOn(commonMain.get())
        }
        getByName("androidMain").dependsOn(jvmSharedMain)
        getByName("desktopMain").dependsOn(jvmSharedMain)
        if (usesPrebuiltDesktop) {
            getByName("desktopMain").resources.srcDir(prebuiltDesktop)
        } else {
            getByName("desktopMain").resources.srcDir(checkNotNull(cargoBuildDesktop))
        }

        commonMain {
            dependencies {
                implementation(libs.kermit)
                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.serialization.json)
            }
        }
        commonTest {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.kotlinx.coroutines.test)
            }
        }
    }
}

extensions.configure<KotlinMultiplatformAndroidComponentsExtension> {
    onVariants { variant ->
        if (usesPrebuiltAndroid) {
            variant.sources.jniLibs?.addStaticSourceDirectory(prebuiltAndroidNatives.asFile.absolutePath)
        } else {
            variant.sources.jniLibs?.addGeneratedSourceDirectory(
                checkNotNull(cargoBuildAndroid),
                CargoNdkTask::outputDirectory,
            )
        }
    }
}
