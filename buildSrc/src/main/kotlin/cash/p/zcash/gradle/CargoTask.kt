package cash.p.zcash.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.MapProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.File
import javax.inject.Inject

/** Runs cargo and publishes what it produced as a Gradle output directory. */
abstract class CargoTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val rustSources: ConfigurableFileCollection

    @get:Input
    abstract val cargoBinary: Property<String>

    @get:Input
    abstract val arguments: ListProperty<String>

    @get:Input
    abstract val cargoEnvironment: MapProperty<String, String>

    @get:Internal
    abstract val workspace: DirectoryProperty

    @get:OutputDirectory
    abstract val outputDirectory: DirectoryProperty

    @get:Inject
    protected abstract val execOperations: ExecOperations

    protected fun cargo(vararg extraArguments: String) {
        execOperations.exec {
            commandLine(listOf(cargoBinary.get()) + arguments.get() + extraArguments)
            environment(cargoEnvironment.get())
            workingDir(workspace.get().asFile)
        }
    }
}

/** cargo-ndk already emits the `<abi>/lib*.so` layout jniLibs expects. */
abstract class CargoNdkTask : CargoTask() {

    @get:Input
    abstract val libraryName: Property<String>

    @TaskAction
    fun build() {
        val output = outputDirectory.get().asFile
        cargo("-o", output.absolutePath)
        // Upstream rlz also declares a cdylib; cargo-ndk copies it, doubling the payload.
        val keep = libraryName.get()
        output.walkTopDown().filter { it.isFile && it.name != keep }.forEach(File::delete)
    }
}

/** Desktop unpacks the binary from the jar, so stage it under `native/<triple>/`. */
abstract class CargoHostTask : CargoTask() {

    @get:Input
    abstract val hostTriple: Property<String>

    @get:Internal
    abstract val binary: RegularFileProperty

    @TaskAction
    fun build() {
        cargo()
        val source = binary.get().asFile
        val target = outputDirectory.get().dir("native/${hostTriple.get()}").asFile
        target.mkdirs()
        source.copyTo(target.resolve(source.name), overwrite = true)
    }
}
