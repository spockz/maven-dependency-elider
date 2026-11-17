/* WHY: Centralizes Maven coordinates and lifecycle phase names for dependency-elider. */

package io.github.spockz.elider.plugin;

import org.apache.maven.model.Plugin;

/** Shared plugin coordinates, goal names, and lifecycle phase constants. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EliderPluginCoordinates {
  /** Plugin Maven groupId. */
  static final String GROUP_ID = "io.github.spockz";

  /** Plugin Maven artifactId. */
  static final String ARTIFACT_ID = "dependency-elider-maven-plugin";

  /** Maven plugin CLI prefix. */
  static final String PREFIX = "dependency-elider";

  /** Elide goal name. */
  static final String ELIDE_GOAL = "elide";

  /** Validate goal name. */
  static final String VALIDATE_GOAL = "validate";

  /** Validate lifecycle phase name. */
  static final String VALIDATE_PHASE = "validate";

  /** Legacy initialize lifecycle phase name. */
  static final String INITIALIZE_PHASE = "initialize";

  /** Default post-compile lifecycle phase name. */
  static final String PROCESS_CLASSES_PHASE = "process-classes";

  private EliderPluginCoordinates() {}

  static boolean isEliderPlugin(final Plugin plugin) {
    return plugin != null
        && GROUP_ID.equals(plugin.getGroupId())
        && ARTIFACT_ID.equals(plugin.getArtifactId());
  }

  static boolean matches(final String groupId, final String artifactId) {
    return GROUP_ID.equals(groupId) && ARTIFACT_ID.equals(artifactId);
  }
}
