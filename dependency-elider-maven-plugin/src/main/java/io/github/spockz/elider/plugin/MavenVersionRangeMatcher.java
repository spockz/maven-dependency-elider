// WHY: Makes Maven's recommended-version syntax exact while honoring explicit range bounds.

package io.github.spockz.elider.plugin;

import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.VersionRange;

/** Evaluates an advisory version specification against one resolved Maven version. */
final class MavenVersionRangeMatcher {
  private MavenVersionRangeMatcher() {}

  static boolean includes(final String specification, final String version) {
    try {
      final VersionRange range = VersionRange.createFromVersionSpec(specification);
      if (range.hasRestrictions()) {
        return range.containsVersion(new DefaultArtifactVersion(version));
      }
      final org.apache.maven.artifact.versioning.ArtifactVersion recommended =
          range.getRecommendedVersion();
      return recommended != null
          && new ComparableVersion(recommended.toString()).compareTo(new ComparableVersion(version))
              == 0;
    } catch (final InvalidVersionSpecificationException | IllegalArgumentException exception) {
      return false;
    }
  }
}
