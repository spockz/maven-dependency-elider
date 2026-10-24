package io.github.spockz.elider.model;

import java.io.Serializable;
import java.util.Comparator;
import java.util.Objects;

/** Immutable coordinate identifying a Maven dependency artifact. */
public record ArtifactCoordinate(
    String groupId, String artifactId, String version, String type, String classifier, String scope)
    implements Serializable, Comparable<ArtifactCoordinate> {

  /** Keeps natural ordering consistent with equality across all record components. */
  private static final Comparator<ArtifactCoordinate> ORDER =
      Comparator.comparing(ArtifactCoordinate::groupId)
          .thenComparing(ArtifactCoordinate::artifactId)
          .thenComparing(ArtifactCoordinate::version, Comparator.nullsFirst(String::compareTo))
          .thenComparing(ArtifactCoordinate::type)
          .thenComparing(ArtifactCoordinate::classifier)
          .thenComparing(ArtifactCoordinate::scope);

  /** Validates identity fields and applies defaults to optional Maven fields. */
  public ArtifactCoordinate {
    Objects.requireNonNull(groupId, "groupId must not be null");
    Objects.requireNonNull(artifactId, "artifactId must not be null");
    if (type == null || type.isBlank()) {
      type = "jar";
    }
    if (classifier == null) {
      classifier = "";
    }
    if (scope == null || scope.isBlank()) {
      scope = "compile";
    }
  }

  /** Creates a JAR coordinate using Maven's default compile scope. */
  public static ArtifactCoordinate of(
      final String groupId, final String artifactId, final String version) {
    return new ArtifactCoordinate(groupId, artifactId, version, "jar", "", "compile");
  }

  /** Returns the artifact key used by Maven, including the classifier when present. */
  public String toId() {
    final String baseId = groupId + ":" + artifactId + ":" + type;
    return classifier.isBlank()
        ? baseId + ":" + version
        : baseId + ":" + classifier + ":" + version;
  }

  /** Returns the group and artifact portion used to match related artifacts. */
  public String toShortKey() {
    return groupId + ":" + artifactId;
  }

  /** Keeps natural ordering consistent with equality across all record components. */
  @Override
  public int compareTo(final ArtifactCoordinate other) {
    return ORDER.compare(this, other);
  }

  /** Adds the Maven scope to the artifact key for build diagnostics. */
  @Override
  public String toString() {
    return toId() + " (" + scope + ")";
  }
}
