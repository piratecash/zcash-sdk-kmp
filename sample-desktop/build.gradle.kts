import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The Kotlin Gradle plugin is already on the build classpath via :zcash-sdk; a versioned
// request here would fail as an unresolvable version conflict.
plugins {
    id("org.jetbrains.kotlin.jvm")
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
}

kotlin {
    jvmToolchain(21)

    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
}

dependencies {
    implementation(project(":sample-shared"))
    implementation(compose.desktop.currentOs)

    // Supplies Dispatchers.Main on the JVM; without it the first launch on the main scope throws.
    implementation(libs.kotlinx.coroutines.swing)
}

compose.desktop {
    application {
        mainClass = "cash.p.zcash.demo.desktop.MainKt"
    }
}
