/* WHY: Proves external Graal configuration bytes stay bound to analysis and publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import io.github.spockz.elider.plugin.nativeimage.NativeImageConfigurationPointerTestSupport;
import io.github.spockz.elider.plugin.nativeimage.NativeImageScanContext;
import io.github.spockz.elider.plugin.nativeimage.NativeImageScanContextTestSupport;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
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

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar, context);

    NativeImageExternalConfigurationInputTestSupport.assertExternalReflectionScan(scan, descriptor);
  }

  /* package */
  @Test
  void everyTypedPointerUsesItsDeclaredKindForArbitraryNames() throws IOException {
    int index = 0;
    for (final NativeImageConfigurationPointerTestSupport.PointerCase pointer :
        NativeImageConfigurationPointerTestSupport.pointerCases()) {
      final String reference = "descriptor-" + index + ".payload";
      final String descriptor =
          NativeImageConfigurationPointerTestSupport.descriptor(pointer.kind());
      final Path declaring =
          NativeImageScanContextTestSupport.jar(
              inputDirectory,
              "dispatch-declaring-" + index + ".jar",
              NativeImageScanContextTestSupport.entries(
                  NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                  "Args = " + pointer.option() + "=" + reference + "\n"));
      final NativeImageScanContext context;
      if (pointer.resource()) {
        final Path provider =
            NativeImageScanContextTestSupport.jar(
                inputDirectory,
                "dispatch-provider-" + index + ".jar",
                NativeImageScanContextTestSupport.entries(reference, descriptor));
        context =
            NativeImageScanContext.create(
                List.of(
                    NativeImageScanContextTestSupport.candidate("declaring", declaring),
                    NativeImageScanContextTestSupport.candidate("provider", provider)),
                inputDirectory);
      } else {
        Files.writeString(inputDirectory.resolve(reference), descriptor);
        context =
            NativeImageExternalConfigurationInputTestSupport.context(declaring, inputDirectory);
      }
      final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

      NativeImageConfigurationPointerTestSupport.assertDispatch(scan, pointer, reference);
      index++;
    }
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
            jar, NativeImageExternalConfigurationInputTestSupport.context(jar, inputDirectory));

    NativeImageExternalConfigurationInputTestSupport.assertPredefinedScan(scan, hash);
  }

  /* package */
  @Test
  void arbitraryPredefinedResourceReadsItsSiblingClassData() throws IOException {
    final String hash = "abcdef0123456789abcdef0123456789";
    final String resourceName = "arbitrary-predefined.blob";
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            inputDirectory,
            "predefined-resource-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:PredefinedClassesConfigurationResources=" + resourceName + "\n"));
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC,
        "org/example/ResourceGenerated",
        null,
        "org/example/ResourceDependency",
        null);
    writer.visitEnd();
    final Path provider = inputDirectory.resolve("predefined-resource-provider.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(provider))) {
      writeJarEntry(
          output,
          resourceName,
          ("[{\"type\":\"agent-extracted\",\"classes\":[{\"hash\":\"" + hash + "\"}]}]")
              .getBytes(java.nio.charset.StandardCharsets.UTF_8));
      writeJarEntry(
          output,
          "agent-extracted-predefined-classes/" + hash + ".classdata",
          writer.toByteArray());
    }
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate("declaring", declaring),
                NativeImageScanContextTestSupport.candidate("provider", provider)),
            inputDirectory);

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    NativeImageConfigurationPointerTestSupport.assertPredefinedResourceScan(scan, provider);
  }

  private static void writeJarEntry(
      final JarOutputStream output, final String name, final byte[] bytes) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }
}
