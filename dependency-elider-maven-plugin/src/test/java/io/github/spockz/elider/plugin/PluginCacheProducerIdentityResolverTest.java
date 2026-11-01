/* WHY: Verifies cache producer identity comes from installed Maven plugin artifacts. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies persistent cache identity follows installed plugin artifacts. */
class PluginCacheProducerIdentityResolverTest {
  /** Maven group shared by the plugin and core test artifacts. */
  private static final String PLUGIN_GROUP_ID = "io.github.spockz";

  /** Plugin artifact identifier used in descriptor fixtures. */
  private static final String PLUGIN_ARTIFACT_ID = "dependency-elider";

  /** Core artifact identifier used in snapshot realm fixtures. */
  private static final String CORE_ARTIFACT_ID = "elider-core";

  /** Released plugin version used in exact GAV fixtures. */
  private static final String RELEASE_VERSION = "1.2.3";

  /** Deliberately mismatched artifact version. */
  private static final String MISMATCH_VERSION = "1.2.4";

  /** Snapshot version used in byte-derived identity fixtures. */
  private static final String SNAPSHOT_VERSION = "1.2.3-SNAPSHOT";

  /** Temporary files stand in for resolved installed plugin artifacts. */
  @TempDir private Path directory;

  /** Creates one isolated resolver test fixture. */
  /* package */
  PluginCacheProducerIdentityResolverTest() {
    // JUnit creates one instance per test method.
  }

  @Test
  void releasedIdentityUsesDescriptorAndPluginArtifactGavWithoutRequiringBytes() {
    final PluginDescriptor descriptor =
        descriptor(RELEASE_VERSION, artifact(RELEASE_VERSION, null), List.of());

    final PluginCacheProducerIdentityResolver.Resolution resolution =
        PluginCacheProducerIdentityResolver.resolve(descriptor);

    assertAll(
        () -> assertThat(resolution.identity()).isPresent(),
        () ->
            assertThat(resolution.identity().orElseThrow())
                .satisfies(
                    identity ->
                        assertAll(
                            () -> assertThat(identity.groupId()).isEqualTo(PLUGIN_GROUP_ID),
                            () -> assertThat(identity.artifactId()).isEqualTo(PLUGIN_ARTIFACT_ID),
                            () -> assertThat(identity.version()).isEqualTo(RELEASE_VERSION),
                            () -> assertThat(identity.buildIdentity()).isNull())),
        () -> assertThat(resolution.diagnostic()).isEmpty());
  }

  @Test
  void snapshotIdentityHashesExactPluginAndCoreArtifactBytes() throws Exception {
    final Path pluginJar = directory.resolve("plugin.jar");
    final Path coreJar = directory.resolve("core.jar");
    Files.writeString(pluginJar, "plugin-one");
    Files.writeString(coreJar, "core-one");
    final Artifact pluginArtifact = artifact(SNAPSHOT_VERSION, pluginJar);
    final Artifact coreArtifact =
        artifact(SNAPSHOT_VERSION, PLUGIN_GROUP_ID, CORE_ARTIFACT_ID, coreJar);
    final PluginDescriptor descriptor =
        descriptor(SNAPSHOT_VERSION, pluginArtifact, List.of(coreArtifact));

    final String first =
        PluginCacheProducerIdentityResolver.resolve(descriptor)
            .identity()
            .orElseThrow()
            .buildIdentity();
    Files.writeString(pluginJar, "plugin-two");
    final String second =
        PluginCacheProducerIdentityResolver.resolve(descriptor)
            .identity()
            .orElseThrow()
            .buildIdentity();
    Files.writeString(coreJar, "core-two");
    final String third =
        PluginCacheProducerIdentityResolver.resolve(descriptor)
            .identity()
            .orElseThrow()
            .buildIdentity();

    assertAll(
        () -> assertThat(first).matches("[0-9a-f]{64}"),
        () -> assertThat(second).matches("[0-9a-f]{64}"),
        () -> assertThat(second).isNotEqualTo(first),
        () -> assertThat(third).isNotEqualTo(second));
  }

  @Test
  void snapshotPersistenceIsDisabledWhenCoreArtifactIsMissingOrAmbiguous() throws Exception {
    final Path pluginJar = directory.resolve("plugin.jar");
    Files.writeString(pluginJar, "plugin");
    final Artifact pluginArtifact = artifact(SNAPSHOT_VERSION, pluginJar);
    final PluginDescriptor missing = descriptor(SNAPSHOT_VERSION, pluginArtifact, List.of());
    final Artifact firstCore =
        artifact(
            SNAPSHOT_VERSION, PLUGIN_GROUP_ID, CORE_ARTIFACT_ID, directory.resolve("core-a.jar"));
    final Artifact secondCore =
        artifact(
            SNAPSHOT_VERSION, PLUGIN_GROUP_ID, CORE_ARTIFACT_ID, directory.resolve("core-b.jar"));
    final PluginDescriptor ambiguous =
        descriptor(SNAPSHOT_VERSION, pluginArtifact, List.of(firstCore, secondCore));

    final PluginCacheProducerIdentityResolver.Resolution missingResolution =
        PluginCacheProducerIdentityResolver.resolve(missing);
    final PluginCacheProducerIdentityResolver.Resolution ambiguousResolution =
        PluginCacheProducerIdentityResolver.resolve(ambiguous);

    assertAll(
        () -> assertThat(missingResolution.identity()).isEmpty(),
        () -> assertThat(missingResolution.diagnostic()).isPresent(),
        () -> assertThat(ambiguousResolution.identity()).isEmpty(),
        () -> assertThat(ambiguousResolution.diagnostic()).isPresent());
  }

  @Test
  void snapshotPersistenceIsDisabledForDirectoryArtifact() throws Exception {
    final Path pluginJar = directory.resolve("plugin.jar");
    Files.createDirectory(pluginJar);
    final Path coreJar = directory.resolve("core.jar");
    Files.writeString(coreJar, "readable-core");
    final Artifact pluginArtifact = artifact(SNAPSHOT_VERSION, pluginJar);
    final Artifact coreArtifact =
        artifact(SNAPSHOT_VERSION, PLUGIN_GROUP_ID, CORE_ARTIFACT_ID, coreJar);
    final PluginDescriptor descriptor =
        descriptor(SNAPSHOT_VERSION, pluginArtifact, List.of(coreArtifact));

    final PluginCacheProducerIdentityResolver.Resolution resolution =
        PluginCacheProducerIdentityResolver.resolve(descriptor);

    assertAll(
        () -> assertThat(resolution.identity()).isEmpty(),
        () ->
            assertThat(resolution.diagnostic())
                .hasValueSatisfying(value -> assertThat(value).contains("bytes are unavailable")));
  }

  @Test
  void descriptorArtifactMismatchCannotProduceIdentity() {
    final PluginDescriptor descriptor =
        descriptor(RELEASE_VERSION, artifact(MISMATCH_VERSION, null), List.of());

    final PluginCacheProducerIdentityResolver.Resolution resolution =
        PluginCacheProducerIdentityResolver.resolve(descriptor);

    assertAll(
        () -> assertThat(resolution.identity()).isEmpty(),
        () ->
            assertThat(resolution.diagnostic())
                .hasValueSatisfying(value -> assertThat(value).contains("does not match")));
  }

  private static PluginDescriptor descriptor(
      final String version, final Artifact pluginArtifact, final List<Artifact> realmArtifacts) {
    final PluginDescriptor descriptor = new PluginDescriptor();
    descriptor.setGroupId(PLUGIN_GROUP_ID);
    descriptor.setArtifactId(PLUGIN_ARTIFACT_ID);
    descriptor.setVersion(version);
    descriptor.setPluginArtifact(pluginArtifact);
    descriptor.setArtifacts(realmArtifacts);
    return descriptor;
  }

  private static Artifact artifact(final String version, final Path file) {
    return artifact(version, PLUGIN_GROUP_ID, PLUGIN_ARTIFACT_ID, file);
  }

  private static Artifact artifact(
      final String version, final String groupId, final String artifactId, final Path file) {
    final Artifact artifact =
        new DefaultArtifact(
            groupId,
            artifactId,
            version,
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    if (file != null) {
      artifact.setFile(file.toFile());
    }
    return artifact;
  }
}
