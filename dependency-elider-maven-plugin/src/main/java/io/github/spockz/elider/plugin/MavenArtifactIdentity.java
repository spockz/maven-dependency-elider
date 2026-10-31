// WHY: Excludes Maven scope from file identity so conflicting artifact views
// are rejected.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;

/** Identity shared by scope-independent artifact selection and path guards. */
record MavenArtifactIdentity(
    String groupId, String artifactId, String version, String type, String classifier) {
  /* package */ static MavenArtifactIdentity from(final ArtifactCoordinate coordinate) {
    return new MavenArtifactIdentity(
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.version(),
        coordinate.type(),
        coordinate.classifier());
  }
}
