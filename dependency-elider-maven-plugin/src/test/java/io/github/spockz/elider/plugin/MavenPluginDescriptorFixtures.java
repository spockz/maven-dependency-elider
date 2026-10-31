/* WHY: Builds valid installed-plugin descriptors for Mojo cache tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.CacheProducerIdentity;
import java.util.List;
import java.util.Optional;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.descriptor.PluginDescriptor;

/** Shared Maven plugin descriptor fixtures. */
final class MavenPluginDescriptorFixtures {
  /** Maven group used by the plugin artifact fixture. */
  private static final String GROUP_ID = "io.github.spockz";

  /** Artifact identifier used by the plugin fixture. */
  private static final String ARTIFACT_ID = "dependency-elider-maven-plugin";

  /** Released plugin version needs no build digest. */
  private static final String RELEASE_VERSION = "1.0.0";

  /** Prevents instances of this static fixture utility. */
  private MavenPluginDescriptorFixtures() {
    // Static fixture methods only.
  }

  /* package */
  static PluginDescriptor releasedPluginDescriptor() {
    final Artifact artifact =
        new DefaultArtifact(
            GROUP_ID,
            ARTIFACT_ID,
            RELEASE_VERSION,
            "runtime",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    final PluginDescriptor descriptor = new PluginDescriptor();
    descriptor.setGroupId(GROUP_ID);
    descriptor.setArtifactId(ARTIFACT_ID);
    descriptor.setVersion(RELEASE_VERSION);
    descriptor.setPluginArtifact(artifact);
    descriptor.setArtifacts(List.of());
    return descriptor;
  }

  /** Supplies a released cache producer. */
  /* package */
  static PluginCacheProducerIdentityResolver.Resolution releasedProducerResolution() {
    return new PluginCacheProducerIdentityResolver.Resolution(
        Optional.of(new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASE_VERSION, null)),
        Optional.empty());
  }

  /** Supplies release identity with optional build metadata for compatibility tests. */
  /* package */
  static PluginCacheProducerIdentityResolver.Resolution releasedProducerResolution(
      final String buildIdentity) {
    return new PluginCacheProducerIdentityResolver.Resolution(
        Optional.of(
            new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, RELEASE_VERSION, buildIdentity)),
        Optional.empty());
  }

  /** Supplies a SNAPSHOT producer. */
  /* package */
  static PluginCacheProducerIdentityResolver.Resolution snapshotProducerResolution(
      final String buildIdentity) {
    return new PluginCacheProducerIdentityResolver.Resolution(
        Optional.of(
            new CacheProducerIdentity(GROUP_ID, ARTIFACT_ID, "1.0.0-SNAPSHOT", buildIdentity)),
        Optional.empty());
  }

  /** Supplies a missing producer. */
  /* package */
  static PluginCacheProducerIdentityResolver.Resolution unavailableProducerResolution() {
    return new PluginCacheProducerIdentityResolver.Resolution(
        Optional.empty(), Optional.of("fixture producer identity is unavailable"));
  }
}
