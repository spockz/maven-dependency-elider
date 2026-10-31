/* WHY: Shares archive and assertion helpers so tests stay focused on input behavior. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/** Utilities for external descriptor and snapshot behavior tests. */
/* package */ final class NativeImageExternalConfigurationInputTestSupport {
  private NativeImageExternalConfigurationInputTestSupport() {
    throw new AssertionError("static fixture holder");
  }

  /* package */ static NativeImageScanContext context(final Path jar, final Path invocationBase)
      throws IOException {
    return NativeImageScanContext.create(
        List.of(NativeImageScanContextTestSupport.candidate("declaring", jar)), invocationBase);
  }

  /* package */ static void assertExternalReflectionScan(
      final DependencyDynamicRoots.RootScan scan, final Path descriptor) throws IOException {
    assertThat(scan.roots()).contains("org.example.External");
    assertThat(scan.consumedInputs())
        .singleElement()
        .satisfies(
            input -> {
              assertThat(input.logicalPath()).isEqualTo(descriptor.toAbsolutePath().normalize());
              assertThat(input.byteLength()).isEqualTo(Files.size(descriptor));
              assertThat(input.role()).contains("REFLECTION");
            });
  }

  /* package */ static void assertPredefinedScan(
      final DependencyDynamicRoots.RootScan scan, final String hash) {
    assertThat(scan.roots())
        .contains("org.example.ExternalGenerated", "org.example.ExternalDependency");
    assertThat(scan.consumedInputs())
        .extracting(input -> input.logicalPath().getFileName().toString())
        .contains("predefined.payload", hash + ".classdata");
  }

  /* package */ static void assertRetargetRejectedBeforePublication(
      final MavenElisionService service,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Path outputDirectory) {
    assertThatThrownBy(() -> service.finish(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("input target changed after preparation");
    assertThat(outputDirectory).doesNotExist();
  }

  /* package */ static Path appendEntries(
      final Path outputDirectory,
      final Path source,
      final String destinationName,
      final Map<String, String> additions)
      throws IOException {
    return appendEntries(outputDirectory, source, destinationName, additions, Map.of());
  }

  /* package */ static Path appendEntries(
      final Path outputDirectory,
      final Path source,
      final String destinationName,
      final Map<String, String> additions,
      final Map<String, byte[]> classAdditions)
      throws IOException {
    final Path destination = outputDirectory.resolve(destinationName);
    try (JarFile archive = new JarFile(source.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(destination))) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        copyEntry(archive, output, entries.nextElement());
      }
      for (final Map.Entry<String, String> addition : additions.entrySet()) {
        writeEntry(output, addition.getKey(), addition.getValue());
      }
      for (final Map.Entry<String, byte[]> addition : classAdditions.entrySet()) {
        writeEntry(output, addition.getKey(), addition.getValue());
      }
    }
    return destination;
  }

  /* package */ static void replaceArtifactFile(
      final MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture,
      final String artifactId,
      final Path replacement) {
    fixture.artifacts().stream()
        .filter(artifact -> artifactId.equals(artifact.getArtifactId()))
        .findFirst()
        .orElseThrow()
        .setFile(replacement.toFile());
  }

  private static void copyEntry(
      final JarFile archive, final JarOutputStream output, final JarEntry entry)
      throws IOException {
    output.putNextEntry(new JarEntry(entry.getName()));
    try (InputStream input = archive.getInputStream(entry)) {
      input.transferTo(output);
    }
    output.closeEntry();
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final String value) throws IOException {
    writeEntry(output, name, value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] value) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(value);
    output.closeEntry();
  }
}
