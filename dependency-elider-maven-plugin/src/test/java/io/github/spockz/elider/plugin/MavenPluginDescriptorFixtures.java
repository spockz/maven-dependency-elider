/* WHY: Builds valid installed-plugin descriptors for Mojo cache tests. */

package io.github.spockz.elider.plugin;

import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.descriptor.PluginDescriptor;

/** Shared Maven plugin descriptor fixtures. */
final class MavenPluginDescriptorFixtures {
  /** Maven group used by the plugin artifact fixture. */
  private static final String GROUP_ID = "io.github.spockz";

  /** Artifact identifier used by the plugin fixture. */
  private static final String ARTIFACT_ID = "dependency-elider";

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
}
