// WHY: Detaches retained artifact paths from Maven objects before sharing them with resolver
// sessions.

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/** Immutable JDK-only replacement plan for one Maven project. */
@SuppressWarnings("PMD.UseConcurrentHashMap")
record ResolverArtifactPlan(
    ProjectIdentity project, Map<ArtifactIdentity, Replacement> replacements) {
  /** Validates expected digests before they enter the detached plan. */
  private static final Pattern SHA_256 = Pattern.compile("[0-9a-f]{64}");

  ResolverArtifactPlan {
    Objects.requireNonNull(project, "project");
    Objects.requireNonNull(replacements, "replacements");
    final Map<ArtifactIdentity, Replacement> normalized = new LinkedHashMap<>();
    replacements.forEach(
        (identity, path) -> {
          Objects.requireNonNull(identity, "artifact identity");
          normalized.put(identity, Objects.requireNonNull(path, "replacement"));
        });
    replacements = Collections.unmodifiableMap(normalized);
  }

  /** Project identity that keeps plans isolated across reactor modules and versions. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record ProjectIdentity(Path baseDirectory, String groupId, String artifactId, String version) {
    ProjectIdentity {
      baseDirectory =
          Objects.requireNonNull(baseDirectory, "baseDirectory").toAbsolutePath().normalize();
      groupId = requireText(groupId, "groupId");
      artifactId = requireText(artifactId, "artifactId");
      version = requireText(version, "version");
    }
  }

  /** Maven Resolver GAVCE key. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record ArtifactIdentity(
      String groupId, String artifactId, String version, String extension, String classifier) {
    ArtifactIdentity {
      groupId = requireText(groupId, "groupId");
      artifactId = requireText(artifactId, "artifactId");
      version = requireText(version, "version");
      extension = requireText(extension, "extension");
      classifier = Objects.requireNonNull(classifier, "classifier");
    }

    boolean hasFamily(
        final String candidateGroupId,
        final String candidateArtifactId,
        final String candidateExtension,
        final String candidateClassifier) {
      return groupId.equals(candidateGroupId)
          && artifactId.equals(candidateArtifactId)
          && extension.equals(candidateExtension)
          && classifier.equals(candidateClassifier);
    }
  }

  /** Detached file location and expected output digest. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record Replacement(Path path, String sha256) {
    Replacement {
      path = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
      if (sha256 == null || !SHA_256.matcher(sha256).matches()) {
        throw new IllegalArgumentException("sha256 must be a lowercase SHA-256 digest");
      }
    }
  }

  private static String requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
    return value;
  }
}
