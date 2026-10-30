// WHY: Verifies scanning and partitioning of ServiceLoader SPI and other dynamic roots.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

  @Test
  void parsesOkHttpArgsAndRetainsFeatureRoot() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = -H:+AddAllCharsets --enable-http --enable-https "
                + "--features=okhttp3.internal.graal.OkHttpFeature "
                + "--report-unsupported-elements-at-runtime\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).contains("okhttp3.internal.graal.OkHttpFeature");
    assertThat(scan.requiresPassThrough()).isFalse();
  }

  @Test
  void loadsJavaPropertiesContinuationBeforeTokenizingArgs() throws IOException {
    final Path jar =
        nativeImageJar("Args = --features=org.example.Feature \\\n" + "  --enable-http\n");

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(jar);

    assertThat(scan.roots()).contains("org.example.Feature");
    assertThat(scan.requiresPassThrough()).isFalse();
  }

  @Test
  void stripsQuotesAndAllowsArgumentsByName() throws IOException {
    final Path jar =
        nativeImageJar(
            "Args = \"-H:ReflectionConfigurationResources=${.}/reflect-config.json\" "
                + "'--enable-http' -H:CustomFlag='some value'\n",
            "META-INF/native-image/test/reflect-config.json",
            "[{\"name\":\"org.example.Reflective\"}]");

    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(
            jar, Set.of("-H:CustomFlag", "-H:ReflectionConfigurationResources"), true);

    assertThat(scan.requiresPassThrough()).isFalse();
    assertThat(scan.roots()).contains("org.example.Reflective");
  }

  @Test
  void fallbackMarksUnsupportedArchiveForPassThroughAndStrictErrorIsActionable()
      throws IOException {
    final Path jar = nativeImageJar("Args = -H:UnknownOption=value\n");

    final DependencyDynamicRoots.RootScan fallback =
        DependencyDynamicRoots.scan(jar, Set.of(), false);

    assertThat(fallback.requiresPassThrough()).isTrue();
    assertThat(fallback.declaresClassRoots()).isFalse();
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar, Set.of(), true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("-H:UnknownOption")
        .hasMessageContaining("full argument: '-H:UnknownOption=value'")
        .hasMessageContaining("META-INF/native-image/test/native-image.properties")
        .hasMessageContaining("<allowedNativeImageArgs>")
        .hasMessageContaining("Or via CLI: -Delide.allowedNativeImageArgs=-H:UnknownOption");
  }

  @Test
  void rejectsUnmatchedQuotes() throws IOException {
    final Path jar = nativeImageJar("Args = --features='org.example.Feature\n");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unmatched quote");
  }

  @Test
  void doesNotAllowBareModeledRootNamesToBypassValidation() throws IOException {
    final Path jar = nativeImageJar("Args = --features\n");
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar, Set.of("--features"), false))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("root option has no value");
  }

  @Test
  void bindsAllowlistAndStrictnessToNativeImageScanPolicy() throws IOException {
    final Path jar = nativeImageJar("Args = -H:CustomFlag=value\n");
    final DependencyDynamicRoots.RootScan allowed =
        DependencyDynamicRoots.scan(jar, Set.of("-H:CustomFlag"), true);
    final DependencyDynamicRoots.RootScan permissive =
        DependencyDynamicRoots.scan(jar, Set.of(), false);

    assertThat(allowed.nativeImagePolicy()).isNotEqualTo(permissive.nativeImagePolicy());
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(jar, Set.of(), true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("-H:CustomFlag");
  }

  private Path nativeImageJar(final String args) throws IOException {
    return nativeImageJar(args, null, null);
  }

  private Path nativeImageJar(final String args, final String extraName, final String extraContent)
      throws IOException {
    final Path jar = tempDir.resolve("native-image-" + System.nanoTime() + ".jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("META-INF/native-image/test/native-image.properties"));
      out.write(args.getBytes(StandardCharsets.UTF_8));
      out.closeEntry();
      if (extraName != null) {
        out.putNextEntry(new JarEntry(extraName));
        out.write(extraContent.getBytes(StandardCharsets.UTF_8));
        out.closeEntry();
      }
    }
    return jar;
  }
}
