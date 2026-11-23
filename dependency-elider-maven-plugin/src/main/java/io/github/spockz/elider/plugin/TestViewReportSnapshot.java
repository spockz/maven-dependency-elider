// WHY: Keeps test-only observations separate from production elision and vulnerability evidence.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** A detached, deterministic observation of one test-view preparation. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record TestViewReportSnapshot(
    int schemaVersion,
    String projectGroupId,
    String projectArtifactId,
    String projectVersion,
    String projectBaseDirectory,
    String productionReportSha256,
    Status status,
    String reason,
    String testOutputDirectory,
    List<InputArtifact> inputArtifacts,
    List<Addition> additions,
    String additionsJar,
    boolean conservativeFallbackUsed) {
  /** The independent, unreleased test report format version. */
  static final int SCHEMA_VERSION = 1;

  /** Distinguishes a completed preparation from a deliberate unavailable observation. */
  enum Status {
    PREPARED,
    UNAVAILABLE
  }

  TestViewReportSnapshot {
    require(schemaVersion == SCHEMA_VERSION, "Unsupported test-view report schema version");
    requireText(projectGroupId, "projectGroupId");
    requireText(projectArtifactId, "projectArtifactId");
    requireText(projectVersion, "projectVersion");
    requireText(projectBaseDirectory, "projectBaseDirectory");
    productionReportSha256 =
        HexDigest.requireSha256(productionReportSha256, "productionReportSha256");
    Objects.requireNonNull(status, "status");
    inputArtifacts =
        Objects.requireNonNull(inputArtifacts, "inputArtifacts").stream()
            .sorted(Comparator.comparing(InputArtifact::identity))
            .toList();
    additions =
        Objects.requireNonNull(additions, "additions").stream()
            .sorted(Comparator.comparing(Addition::identity))
            .toList();
    require(
        unique(inputArtifacts.stream().map(InputArtifact::identity).toList()),
        "Test input artifact identities must be distinct");
    require(
        unique(additions.stream().map(Addition::identity).toList()),
        "Test addition identities must be distinct");
    final Set<String> inputs =
        new HashSet<>(inputArtifacts.stream().map(InputArtifact::identity).toList());
    require(
        additions.stream().allMatch(addition -> inputs.contains(addition.identity())),
        "Test additions must belong to an original input artifact");
    if (status == Status.UNAVAILABLE) {
      requireText(reason, "reason");
      require(
          testOutputDirectory == null
              && additionsJar == null
              && inputArtifacts.isEmpty()
              && additions.isEmpty()
              && !conservativeFallbackUsed,
          "Unavailable test view cannot contain prepared observations");
    } else {
      require(reason == null, "Prepared test view cannot have an unavailable reason");
      requireText(testOutputDirectory, "testOutputDirectory");
      require(
          additions.isEmpty() == (additionsJar == null),
          "Test additions JAR presence disagrees with added classes");
      if (additionsJar != null) {
        requireText(additionsJar, "additionsJar");
      }
    }
  }

  String projectGav() {
    return projectGroupId + ":" + projectArtifactId + ":" + projectVersion;
  }

  int addedClassCount() {
    return additions.stream().mapToInt(row -> row.classes().size()).sum();
  }

  /** One original input and its effective path, if retained. */
  record InputArtifact(String identity, String originalJar, String effectiveJar) {
    InputArtifact {
      requireText(identity, "input artifact identity");
      requireText(originalJar, "originalJar");
      if (effectiveJar != null) {
        requireText(effectiveJar, "effectiveJar");
      }
    }
  }

  /** Classes selected from one original provider for the isolated runtime addition. */
  record Addition(String identity, List<String> classes) {
    Addition {
      requireText(identity, "addition identity");
      classes = Objects.requireNonNull(classes, "classes").stream().sorted().toList();
      require(!classes.isEmpty() && unique(classes), "Added classes must be nonempty and distinct");
      for (final String name : classes) {
        require(validClassEntry(name), "Added class name is invalid: " + name);
      }
    }
  }

  private static boolean validClassEntry(final String name) {
    if (name == null
        || name.isEmpty()
        || name.startsWith("/")
        || name.endsWith("/")
        || name.contains("//")) {
      return false;
    }
    return name.codePoints()
        .noneMatch(
            codePoint ->
                codePoint == '.'
                    || codePoint == ';'
                    || codePoint == '['
                    || codePoint == '\\'
                    || Character.isISOControl(codePoint));
  }

  private static boolean unique(final List<String> values) {
    return values.size() == new HashSet<>(values).size();
  }

  private static void requireText(final String value, final String field) {
    require(value != null && !value.isBlank(), field + " must be nonblank text");
  }

  private static void require(final boolean valid, final String message) {
    if (!valid) {
      throw new IllegalArgumentException(message);
    }
  }
}
