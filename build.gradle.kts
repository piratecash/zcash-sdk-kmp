plugins {
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.android.kmp.library) apply false
}

// JitPack builds a tag and passes it in; local builds fall back to a snapshot.
val libraryVersion: String = providers.environmentVariable("JITPACK_VERSION")
    .orElse(providers.environmentVariable("VERSION"))
    .orElse("0.0.0-SNAPSHOT")
    .get()

allprojects {
    group = "com.github.piratecash.zcash-sdk-kmp"
    version = libraryVersion
}
