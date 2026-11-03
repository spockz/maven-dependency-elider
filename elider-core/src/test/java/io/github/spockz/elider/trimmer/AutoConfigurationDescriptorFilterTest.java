// WHY: Unit tests verifying AutoConfigurationDescriptorFilter preserves external classes and removes owned pruned classes.

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AutoConfigurationDescriptorFilterTest {

  @TempDir Path tempDir;

  @Test
  @DisplayName("filterImports prunes owned removed classes and retains external or kept classes")
  void filterImportsPrunesOwnedRemovedClasses() throws IOException {
    final Path jarPath = tempDir.resolve("test.jar");
    final String importsContent =
        "com.example.OwnedRetained\n"
            + "# A comment line\n"
            + "com.example.OwnedRemoved\n"
            + "org.external.ExternalConfig\n";

    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
      final JarEntry entry = new JarEntry(AutoConfigurationDescriptorFilter.IMPORTS_PATH);
      jos.putNextEntry(entry);
      jos.write(importsContent.getBytes(StandardCharsets.UTF_8));
      jos.closeEntry();
    }

    try (JarFile jarFile = new JarFile(jarPath.toFile())) {
      final JarEntry entry = jarFile.getJarEntry(AutoConfigurationDescriptorFilter.IMPORTS_PATH);
      final Set<String> ownedClasses = Set.of("com.example.OwnedRetained", "com.example.OwnedRemoved");
      final Set<String> retainedClasses = Set.of("com.example.OwnedRetained");

      final Optional<byte[]> result =
          AutoConfigurationDescriptorFilter.filterImports(jarFile, entry, ownedClasses, retainedClasses);

      assertThat(result).isPresent();
      final String filtered = new String(result.get(), StandardCharsets.UTF_8);

      assertAll(
          () -> assertThat(filtered).contains("com.example.OwnedRetained"),
          () -> assertThat(filtered).contains("org.external.ExternalConfig"),
          () -> assertThat(filtered).contains("# A comment line"),
          () -> assertThat(filtered).doesNotContain("com.example.OwnedRemoved"));
    }
  }

  @Test
  @DisplayName("filterImports returns empty when no owned classes were removed")
  void filterImportsReturnsEmptyWhenNoClassesRemoved() throws IOException {
    final Path jarPath = tempDir.resolve("unchanged.jar");
    final String importsContent =
        "com.example.OwnedRetained\n"
            + "org.external.ExternalConfig\n";

    try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
      final JarEntry entry = new JarEntry(AutoConfigurationDescriptorFilter.IMPORTS_PATH);
      jos.putNextEntry(entry);
      jos.write(importsContent.getBytes(StandardCharsets.UTF_8));
      jos.closeEntry();
    }

    try (JarFile jarFile = new JarFile(jarPath.toFile())) {
      final JarEntry entry = jarFile.getJarEntry(AutoConfigurationDescriptorFilter.IMPORTS_PATH);
      final Set<String> ownedClasses = Set.of("com.example.OwnedRetained");
      final Set<String> retainedClasses = Set.of("com.example.OwnedRetained");

      final Optional<byte[]> result =
          AutoConfigurationDescriptorFilter.filterImports(jarFile, entry, ownedClasses, retainedClasses);

      assertThat(result).isEmpty();
    }
  }
}
