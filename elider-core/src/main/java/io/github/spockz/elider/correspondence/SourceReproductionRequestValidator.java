// WHY: Keeps request and archive checks outside the reproduction lifecycle.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Validates caller inputs and archive identities. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SourceReproductionRequestValidator {
  /** JAR extension allowed by the initial non-transformed Java source path. */
  private static final String JAR_TYPE = "jar";

  /** Maven classifier resolved for source/build correspondence. */
  private static final String SOURCES_CLASSIFIER = "sources";

  /** Stable diagnostic label for the original artifact. */
  private static final String ORIGINAL_LABEL = "original";

  /** Stable diagnostic label for the sources artifact. */
  private static final String SOURCES_LABEL = "sources";

  private SourceReproductionRequestValidator() {}

  static ValidatedPaths validate(final SourceReproductionRequest request) throws IOException {
    validateCoordinates(request.candidate(), request.sourcesCoordinate());
    return new ValidatedPaths(
        requireJar(request.originalJar(), ORIGINAL_LABEL + " artifact").toRealPath(),
        requireJar(request.sourcesJar(), SOURCES_LABEL + " artifact").toRealPath());
  }

  static void requireClaimPresence(
      final List<String> files, final List<String> routines, final List<String> sourceEntries)
      throws IOException {
    if (files.isEmpty() && routines.isEmpty()) {
      throw new IOException("At least one structured source or routine claim is required");
    }
    if (sourceEntries.isEmpty()) {
      throw new IOException("Sources archive contains no Java source units");
    }
  }

  static void requireStableArchive(final String label, final String expected, final String actual)
      throws IOException {
    if (!expected.equals(actual)) {
      throw invalidArtifact(label, "artifact changed during source reproduction");
    }
  }

  private static void validateCoordinates(
      final ArtifactCoordinate candidate, final ArtifactCoordinate sourceCoordinate)
      throws IOException {
    if (candidate.version() == null || candidate.version().isBlank()) {
      throw new IOException("Exact candidate version is required");
    }
    final boolean matches =
        candidate.groupId().equals(sourceCoordinate.groupId())
            && candidate.artifactId().equals(sourceCoordinate.artifactId())
            && candidate.version().equals(sourceCoordinate.version())
            && JAR_TYPE.equals(candidate.type())
            && candidate.classifier().isEmpty()
            && JAR_TYPE.equals(sourceCoordinate.type())
            && SOURCES_CLASSIFIER.equals(sourceCoordinate.classifier());
    if (!matches) {
      throw new IOException("Sources artifact does not match the exact candidate GAVCE");
    }
  }

  private static Path requireJar(final Path path, final String label) throws IOException {
    if (path == null) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    final Path fileName = path.getFileName();
    if (!Files.isRegularFile(path) || fileName == null) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    if (!fileName.toString().endsWith(".jar")) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    return path.toAbsolutePath().normalize();
  }

  private static IOException invalidArtifact(final String label, final String reason) {
    return new IOException("The " + label + " " + reason);
  }

  record ValidatedPaths(Path original, Path sources) {}
}
