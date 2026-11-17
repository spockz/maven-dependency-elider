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

  /* package */ static MavenArtifactIdentity parsePassThrough(final String raw) {
    if (raw == null || raw.isBlank()) {
      throw new IllegalArgumentException(
          "elide.trimSkipArtifacts must not contain blank coordinates");
    }
    final String[] parts = raw.trim().split(":", -1);
    if (!validPassThroughParts(parts)) {
      throw new IllegalArgumentException(
          "Invalid elide.trimSkipArtifacts coordinate; expected "
              + "group:artifact:version[:type[:classifier]]: "
              + raw);
    }
    final String type =
        parts.length > 3 && !parts[3].isBlank() ? parts[3] : MavenDependencyTrimmer.JAR_TYPE;
    final String classifier = parts.length > 4 ? parts[4] : "";
    return new MavenArtifactIdentity(parts[0], parts[1], parts[2], type, classifier);
  }

  private static boolean validPassThroughParts(final String... parts) {
    return parts.length >= 3
        && parts.length <= 5
        && !parts[0].isBlank()
        && !parts[1].isBlank()
        && !parts[2].isBlank();
  }

  /* package */ boolean matches(final ArtifactCoordinate coordinate) {
    return coordinate.groupId().equals(groupId)
        && coordinate.artifactId().equals(artifactId)
        && coordinate.version().equals(version)
        && coordinate.type().equals(type)
        && coordinate.classifier().equals(classifier);
  }

  /* package */ String format() {
    return groupId + ":" + artifactId + ":" + version + ":" + type + ":" + classifier;
  }
}
