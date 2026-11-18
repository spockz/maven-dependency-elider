// WHY: Excludes Maven scope from file identity so conflicting artifact views
// are rejected.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;

/** Identity shared by scope-independent artifact selection and path guards. */
record MavenArtifactIdentity(
    String groupId, String artifactId, String version, String type, String classifier) {
  /** Wildcard token for optional coordinate parts. */
  private static final String WILDCARD = "*";

  /** Minimum coordinate segments (`groupId:artifactId`). */
  private static final int MIN_PARTS = 2;

  /** Maximum coordinate segments (`groupId:artifactId:version:type:classifier`). */
  private static final int MAX_PARTS = 5;

  /** Segment index for version. */
  private static final int VERSION_INDEX = 2;

  /** Segment index for type. */
  private static final int TYPE_INDEX = 3;

  /** Segment index for classifier. */
  private static final int CLASSIFIER_INDEX = 4;

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
              + "group:artifact[:version[:type[:classifier]]]: "
              + raw);
    }
    final String version = parseOptionalPart(parts, VERSION_INDEX, true);
    final String type =
        parts.length > TYPE_INDEX && !parts[TYPE_INDEX].isBlank()
            ? parts[TYPE_INDEX].trim()
            : MavenDependencyTrimmer.JAR_TYPE;
    final String classifier = parseOptionalPart(parts, CLASSIFIER_INDEX, false);
    return new MavenArtifactIdentity(parts[0].trim(), parts[1].trim(), version, type, classifier);
  }

  private static String parseOptionalPart(
      final String[] parts, final int index, final boolean blankIsWildcard) {
    if (parts.length <= index) {
      return null;
    }
    final String value = parts[index].trim();
    if (WILDCARD.equals(value) || (blankIsWildcard && value.isEmpty())) {
      return null;
    }
    return value;
  }

  private static boolean validPassThroughParts(final String... parts) {
    return parts.length >= MIN_PARTS
        && parts.length <= MAX_PARTS
        && !parts[0].isBlank()
        && !parts[1].isBlank();
  }

  /* package */ boolean matches(final ArtifactCoordinate coordinate) {
    return coordinate.groupId().equals(groupId)
        && coordinate.artifactId().equals(artifactId)
        && (version == null || coordinate.version().equals(version))
        && coordinate.type().equals(type)
        && (classifier == null || coordinate.classifier().equals(classifier));
  }

  /* package */ String format() {
    return groupId + ":" + artifactId + ":" + version + ":" + type + ":" + classifier;
  }
}
