// WHY: Verifies scanning and partitioning of ServiceLoader SPI and other dynamic roots.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests dependency dynamic roots scanning and effective roots partitioning. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AtLeastOneConstructor"
})
final class DependencyDynamicRootsTest {
  /** Test service interface name. */
  private static final String MY_SERVICE = "org.example.spi.MyService";

  /** Dummy class byte payload. */
  private static final byte[] DUMMY_BYTE = {0};

  /** Temporary test directory. */
  @TempDir Path tempDir;

  @Test
  void distinguishesProvenAndUnprovenServiceRoots() throws IOException {
    final Path jar = tempDir.resolve("spi-service.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("org/example/spi/MyService.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/MyServiceImpl.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/OtherService.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("org/example/spi/OtherServiceImpl.class"));
      out.write(DUMMY_BYTE);
      out.closeEntry();
      out.putNextEntry(new JarEntry("META-INF/services/" + MY_SERVICE));
      out.write("org.example.spi.MyServiceImpl\n".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
      out.putNextEntry(new JarEntry("META-INF/services/org.example.spi.OtherService"));
      out.write("org.example.spi.OtherServiceImpl\n".getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
    }

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);
    assertThat(scan.declaresClassRoots()).isTrue();
    assertThat(scan.serviceDescriptors()).hasSize(2);

    // Case 1: MyService is proven, OtherService is not. Fallback enabled (default).
    final DependencyDynamicRoots.EffectiveRoots conservative =
        scan.effectiveRoots(Set.of(MY_SERVICE), true);

    assertThat(conservative.roots())
        .contains(
            MY_SERVICE,
            "org.example.spi.MyServiceImpl",
            "org.example.spi.OtherService",
            "org.example.spi.OtherServiceImpl");
    assertThat(conservative.unprovenConservativeRoots())
        .containsExactlyInAnyOrder(
            "org.example.spi.OtherService", "org.example.spi.OtherServiceImpl");

    // Case 2: MyService is proven, OtherService is not. Fallback disabled.
    final DependencyDynamicRoots.EffectiveRoots nonConservative =
        scan.effectiveRoots(Set.of(MY_SERVICE), false);

    assertThat(nonConservative.roots())
        .containsExactlyInAnyOrder(MY_SERVICE, "org.example.spi.MyServiceImpl");
    assertThat(nonConservative.unprovenConservativeRoots()).isEmpty();
    assertThat(nonConservative.unprovenConservativeServices()).isEmpty();
  }
}
