/* WHY: Proves analysis sees the same effective multi-release classes as the executing JVM. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies release-specific archive flattening for ProGuard library inputs. */
// JUnit uses the generated constructor for this package-private test.
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MultiReleaseLibraryProjectionTest {
  /** Root module descriptor entry excluded from classpath projections. */
  private static final String MODULE_INFO_ENTRY = "module-info.class";

  /** Ordinary class entry used in projection fixtures. */
  private static final String API_ENTRY = "projection/Api.class";

  /** Versioned class entry used to verify effective override selection. */
  private static final String VERSIONED_API_ENTRY = "META-INF/versions/21/" + API_ENTRY;

  /** Temporary fixture root supplied by JUnit. */
  @TempDir private Path temporaryDirectory;

  @Test
  void selectsTheEffectiveOverrideAndVersionOnlyClassesForJavaNineAndTwentyOne()
      throws IOException, ReflectiveOperationException {
    final Path base =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "base",
            8,
            "package projection; public class Api { public static String value() { "
                + "return \"base\"; } }");
    final Path versionNine =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "version-nine",
            9,
            "package projection; public class Api { public static String value() { "
                + "return \"nine\"; } }");
    final Path versionNineOnly =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "version-nine-only",
            9,
            "package projection; public class NineOnly {}");
    final Path versionTwentyOne =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "version-twenty-one",
            21,
            "package projection; public class Api { public static String value() { "
                + "return \"twenty-one\"; } }");
    final Path versionTwentyOneOnly =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "version-twenty-one-only",
            21,
            "package projection; public class TwentyOneOnly {}");
    final Path multiRelease =
        MultiReleaseProjectionFixtures.createMultiReleaseJar(
            temporaryDirectory,
            base,
            versionNine,
            versionNineOnly,
            versionTwentyOne,
            versionTwentyOneOnly);
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "projection", "1.0", "jar", "", "runtime");

    final Path nineProjection =
        MultiReleaseLibraryProjection.create(
            multiRelease, coordinate, temporaryDirectory.resolve("nine"), 9);
    final Path twentyOneProjection =
        MultiReleaseLibraryProjection.create(
            multiRelease, coordinate, temporaryDirectory.resolve("twenty-one"), 21);

    assertThat(
            List.of(
                MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses(multiRelease),
                observe(nineProjection),
                observe(twentyOneProjection)))
        .containsExactly(
            true,
            new ProjectionBehavior("nine", true, false, false, false),
            new ProjectionBehavior("twenty-one", true, true, false, false));
  }

  @Test
  void omitsRootModuleDescriptorOnlyFromPassThroughAnalysisProjection()
      throws IOException, ReflectiveOperationException {
    final Path modularJar = MultiReleaseProjectionFixtures.compileModularJar(temporaryDirectory);
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "modular", "1.0", "jar", "", "runtime");

    final Path projection =
        MultiReleaseLibraryProjection.create(
            modularJar, coordinate, temporaryDirectory.resolve("modular"), 21);

    assertThat(observeModuleProjection(modularJar, projection))
        .isEqualTo(new ModuleProjectionBehavior(true, true, false, true, true));
  }

  private static ProjectionBehavior observe(final Path projection)
      throws IOException, ReflectiveOperationException {
    try (URLClassLoader loader = new URLClassLoader(new URL[] {projection.toUri().toURL()})) {
      final String value =
          (String) loader.loadClass("projection.Api").getMethod("value").invoke(null);
      return new ProjectionBehavior(
          value,
          classAvailable(loader, "projection.NineOnly"),
          classAvailable(loader, "projection.TwentyOneOnly"),
          jarContains(projection, VERSIONED_API_ENTRY),
          jarContains(projection, MODULE_INFO_ENTRY));
    }
  }

  private static ModuleProjectionBehavior observeModuleProjection(
      final Path original, final Path projection) throws IOException, ReflectiveOperationException {
    final boolean descriptorPresent =
        MultiReleaseLibraryProjection.hasRootModuleDescriptor(original);
    try (URLClassLoader loader = new URLClassLoader(new URL[] {projection.toUri().toURL()})) {
      return new ModuleProjectionBehavior(
          descriptorPresent,
          !projection.equals(original),
          jarContains(projection, MODULE_INFO_ENTRY),
          jarContains(projection, API_ENTRY),
          classAvailable(loader, "projection.Api"));
    }
  }

  private static boolean classAvailable(final ClassLoader loader, final String className) {
    try {
      loader.loadClass(className);
      return true;
    } catch (final ClassNotFoundException exception) {
      return false;
    }
  }

  private static boolean jarContains(final Path archivePath, final String entryName)
      throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.getEntry(entryName) != null;
    }
  }

  private record ProjectionBehavior(
      String apiValue,
      boolean nineOnlyAvailable,
      boolean twentyOneOnlyAvailable,
      boolean versionedApiEntryPresent,
      boolean moduleDescriptorPresent) {}

  private record ModuleProjectionBehavior(
      boolean originalHasDescriptor,
      boolean projectionIsDistinct,
      boolean projectionHasDescriptor,
      boolean projectionHasApi,
      boolean apiLoads) {}

  @Test
  void rejectsMalformedRootModuleDescriptorBeforeProjection() throws IOException {
    final Path ordinaryClass =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory, "ordinary", 8, "package projection; public class Ordinary {}");
    final Path malformed = temporaryDirectory.resolve("malformed-" + MODULE_INFO_ENTRY + ".jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(malformed))) {
      MultiReleaseProjectionFixtures.addClass(output, ordinaryClass, MODULE_INFO_ENTRY);
    }

    assertThatThrownBy(() -> MultiReleaseLibraryProjection.hasRootModuleDescriptor(malformed))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Invalid " + MODULE_INFO_ENTRY);
  }
}
