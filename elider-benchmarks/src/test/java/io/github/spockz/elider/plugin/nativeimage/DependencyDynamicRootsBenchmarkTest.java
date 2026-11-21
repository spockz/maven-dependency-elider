/* WHY: Checks that the JMH pair measures equivalent metadata scan results. */

package io.github.spockz.elider.plugin.nativeimage;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"PMD.CommentRequired", "PMD.AtLeastOneConstructor"})
final class DependencyDynamicRootsBenchmarkTest {
  @Test
  void comparesEquivalentScanResults() throws IOException {
    final DependencyDynamicRootsBenchmark benchmark = new DependencyDynamicRootsBenchmark();
    benchmark.setUp();
    try {
      assertAll(
          () ->
              assertEquals(
                  benchmark.referenceOrdinaryJarScan(),
                  benchmark.currentOrdinaryJarScan(),
                  "ordinary archive with no declarations"),
          () -> {
            final DependencyDynamicRoots.RootScan currentMetadata =
                benchmark.currentMetadataJarScan();
            assertAll(
                () ->
                    assertEquals(
                        benchmark.referenceMetadataJarScan(),
                        currentMetadata,
                        "archive declaring SPI and native-image roots"),
                () ->
                    assertEquals(
                        Set.of("sample.Service", "sample.Provider", "sample.Reflective"),
                        currentMetadata.roots(),
                        "the paired workload must actually parse both metadata inputs"));
          });
    } finally {
      benchmark.tearDown();
    }
  }

  @Test
  void matchesReferenceFailureForMalformedMetadata(@TempDir final Path directory)
      throws IOException {
    final Path jar = directory.resolve("invalid.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new JarEntry("META-INF/native-image/library/unknown.json"));
      output.closeEntry();
    }
    final IOException reference =
        assertThrows(IOException.class, () -> ReferenceDependencyDynamicRoots.scan(jar));
    final IOException current =
        assertThrows(IOException.class, () -> DependencyDynamicRoots.scan(jar));
    assertEquals(
        reference.getMessage(),
        current.getMessage(),
        "a rejected descriptor must retain the same path and failure reason");
  }
}
