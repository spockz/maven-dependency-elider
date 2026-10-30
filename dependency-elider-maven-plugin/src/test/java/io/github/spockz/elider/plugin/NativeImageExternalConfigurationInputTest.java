/* WHY: Proves external Graal configuration bytes stay bound to analysis and publication. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Verifies typed external descriptor snapshots and their publication boundary. */
/* package */ final class NativeImageExternalConfigurationInputTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Temporary directory for source-neutral file inputs. */
  /* package */ @TempDir Path inputDirectory;

  /** Creates this focused external-input test group. */
  /* package */ NativeImageExternalConfigurationInputTest() {
    super();
  }

  /* package */
  @Test
  void arbitraryFileNameUsesExplicitReflectionKindAndCapturesItsBytes() throws IOException {
    final Path jar =
        NativeImageScanContextTestSupport.jar(
            inputDirectory,
            "declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ReflectionConfigurationFiles=reflection.payload\n"));
    final Path descriptor = inputDirectory.resolve("reflection.payload");
    Files.writeString(
        descriptor, NativeImageScanContextTestSupport.reflection("org.example.External"));
    final NativeImageScanContext context =
        NativeImageExternalConfigurationInputTestSupport.context(jar, inputDirectory);

    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(jar, context, Set.of(), true);

    NativeImageExternalConfigurationInputTestSupport.assertExternalReflectionScan(scan, descriptor);
  }

  /* package */
  @Test
  void predefinedFileSnapshotsItsSiblingClassData() throws IOException {
    final Path jar =
        NativeImageScanContextTestSupport.jar(
            inputDirectory,
            "predefined-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:PredefinedClassesConfigurationFiles=predefined.payload\n"));
    final String hash = "0123456789abcdef0123456789abcdef";
    final Path descriptor = inputDirectory.resolve("predefined.payload");
    Files.writeString(
        descriptor, "[{\"type\":\"agent-extracted\",\"classes\":[{\"hash\":\"" + hash + "\"}]}]");
    final Path classDataDirectory = inputDirectory.resolve("agent-extracted-predefined-classes");
    Files.createDirectories(classDataDirectory);
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "org/example/ExternalGenerated",
        null,
        "org/example/ExternalDependency",
        null);
    writer.visitEnd();
    final Path classData = classDataDirectory.resolve(hash + ".classdata");
    Files.write(classData, writer.toByteArray());

    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(
            jar,
            NativeImageExternalConfigurationInputTestSupport.context(jar, inputDirectory),
            Set.of(),
            true);

    NativeImageExternalConfigurationInputTestSupport.assertPredefinedScan(scan, hash);
  }

  /* package */
  @Test
  void contentChangesWithPreservedSizeAndMtimeInvalidateSnapshot() throws IOException {
    final Path descriptor = inputDirectory.resolve("same-size.payload");
    Files.writeString(descriptor, "[1,2,3]");
    final NativeImageInput input =
        NativeImageInput.file(descriptor, NativeImageDescriptorKind.REFLECTION);
    input.open().close();
    final NativeImageConsumedInput snapshot = input.consumedInputs().get(0);
    final FileTime originalTime = Files.getLastModifiedTime(descriptor);
    Files.writeString(descriptor, "[1,2,4]");
    Files.setLastModifiedTime(descriptor, originalTime);

    assertThatThrownBy(() -> NativeImageConsumedInput.verifyAll(List.of(snapshot)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("content changed");
  }

  /* package */
  @Test
  void symlinkRetargetToEqualBytesInvalidatesSnapshot() throws IOException {
    final Path firstTarget = inputDirectory.resolve("first-target.payload");
    final Path secondTarget = inputDirectory.resolve("second-target.payload");
    final Path logicalPath = inputDirectory.resolve("linked.payload");
    Files.writeString(firstTarget, "same");
    Files.writeString(secondTarget, "same");
    Files.createSymbolicLink(logicalPath, firstTarget.getFileName());
    final NativeImageInput input =
        NativeImageInput.file(logicalPath, NativeImageDescriptorKind.REFLECTION);
    input.open().close();
    final NativeImageConsumedInput snapshot = input.consumedInputs().get(0);
    Files.delete(logicalPath);
    Files.createSymbolicLink(logicalPath, secondTarget.getFileName());

    assertThatThrownBy(() -> NativeImageConsumedInput.verifyAll(List.of(snapshot)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("target changed");
  }

  /* package */
  @Test
  void mutationAfterPrepareFailsBeforeFinishCanPublish() throws IOException, MojoFailureException {
    final Fixture fixture = fixture(false, false, false);
    final Path declaring =
        NativeImageExternalConfigurationInputTestSupport.appendEntries(
            temporaryDirectory,
            fixture.snapshot("a").filePath(),
            "a-with-external-pointer.jar",
            java.util.Map.of(
                "META-INF/native-image/test/native-image.properties",
                "Args = -H:ReflectionConfigurationFiles=external-reflection.payload\n"));
    NativeImageExternalConfigurationInputTestSupport.replaceArtifactFile(fixture, "a", declaring);
    final Path descriptor = temporaryDirectory.resolve("external-reflection.payload");
    Files.writeString(descriptor, NativeImageScanContextTestSupport.reflection("closure.c.Leaf"));
    final Path trace = temporaryDirectory.resolve("external-pointer-trace.lst");
    Files.writeString(trace, "closure.a.Entry\n");
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, true));
    Files.writeString(
        descriptor, NativeImageScanContextTestSupport.reflection("closure.d.Ancestor"));

    assertThatThrownBy(() -> service.finish(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("content changed");
  }
}
