/* WHY: Proves IncludeResourceBundles keeps class and locale-resource providers. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies resource bundle providers participate in dynamic-root retention. */
/* package */ final class NativeImageBundleRetentionTest {
  /** Shared body for class resource fixtures. */
  /* package */ static final String CLASS_BYTES = "class-bytes";

  /** WHY: Uses the requested locale-qualified bundle name in the fixture. */
  /* package */ private final String bundleName;

  /** WHY: Holds archive fixtures used by provider lookup. */
  /* package */ @TempDir Path tempDir;

  /* package */
  NativeImageBundleRetentionTest() {
    bundleName = "org.example.Messages_en__POSIX";
  }

  /* package */
  @Test
  void retainsDeclaringArchiveAndCrossArchiveBundleProviders() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "bundle-declaring.jar",
            NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
            "Args = -H:IncludeResourceBundles=" + bundleName + "\n");
    final Path classProvider = multiReleaseBundleClass();
    final Path basePropertiesProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir, "bundle-properties.jar", "org/example/Messages.properties", "message=value");
    final Path frenchPropertiesProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "bundle-properties-fr.jar",
            "org/example/Messages_fr.properties",
            "message=fr");
    final Path frenchClassProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir, "bundle-class-fr.jar", "org/example/Messages_fr.class", CLASS_BYTES);
    final Path localeFamilyProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "bundle-locales.jar",
            "org/example/Messages_en-US.properties",
            "message=hyphen",
            "org/example/Messages__US.properties",
            "message=empty-country",
            "org/example/Messages_en__POSIX.properties",
            "message=variant",
            "org/example/Messages_en-US.class",
            CLASS_BYTES,
            "org/example/Messages__US.class",
            CLASS_BYTES);
    final Path prefixCollision =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "bundle-prefix-collision.jar",
            "org/example/MessagesExtra.properties",
            "message=unrelated");
    final ArtifactFileRef declaringCandidate = candidate("declaring", declaring);
    final ArtifactFileRef classCandidate = candidate("class-provider", classProvider);
    final ArtifactFileRef basePropertiesCandidate =
        candidate("base-properties-provider", basePropertiesProvider);
    final ArtifactFileRef frenchPropertiesCandidate =
        candidate("french-properties-provider", frenchPropertiesProvider);
    final ArtifactFileRef frenchClassCandidate =
        candidate("french-class-provider", frenchClassProvider);
    final ArtifactFileRef localeFamilyCandidate = candidate("locale-family", localeFamilyProvider);
    final ArtifactFileRef prefixCollisionCandidate = candidate("prefix-collision", prefixCollision);
    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(
            declaring,
            NativeImageScanContext.create(
                List.of(
                    declaringCandidate,
                    classCandidate,
                    basePropertiesCandidate,
                    frenchPropertiesCandidate,
                    frenchClassCandidate,
                    localeFamilyCandidate,
                    prefixCollisionCandidate),
                null),
            Set.of(),
            true);

    assertThat(List.of(scan.roots(), scan.requiresArtifactRetention(), scan.resourceProviders()))
        .containsExactly(
            Set.of(
                "org.example.Messages_fr",
                "org.example.Messages_en_US",
                "org.example.Messages_en-US",
                "org.example.Messages__US"),
            true,
            Set.of(
                classProvider.toRealPath(),
                basePropertiesProvider.toRealPath(),
                frenchPropertiesProvider.toRealPath(),
                frenchClassProvider.toRealPath(),
                localeFamilyProvider.toRealPath()));
  }

  private ArtifactFileRef candidate(final String artifact, final Path path) throws IOException {
    return ArtifactFileRef.fromPath(ArtifactCoordinate.of("org.example", artifact, "1.0"), path);
  }

  private Path multiReleaseBundleClass() throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    final Path archive = tempDir.resolve("bundle-class-mr.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive), manifest)) {
      output.putNextEntry(new JarEntry("META-INF/versions/17/org/example/Messages_en_US.class"));
      output.write(CLASS_BYTES.getBytes(StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return archive;
  }
}
