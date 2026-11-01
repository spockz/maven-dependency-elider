// WHY: Converts Maven Resolver output into an exact, repository-bound source artifact.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.resolution.ArtifactResult;

/** Validates the resolved source artifact and preserves its origin. */
final class MavenSourceArtifactResult {
  private MavenSourceArtifactResult() {}

  @SuppressWarnings("PMD.LawOfDemeter") // Aether exposes the result through nested artifact APIs.
  /* default */ static MavenSourceClassifierResolver.ResolvedSourceArtifact convert(
      final ArtifactCoordinate candidate,
      final Artifact expected,
      final ArtifactResult result,
      final RepositorySystemSession session)
      throws IOException {
    final Artifact resolved = result.getArtifact();
    if (resolved == null || resolved.getFile() == null || !result.isResolved()) {
      throw new IOException("Maven did not resolve the exact sources artifact " + expected);
    }
    if (!sameArtifact(expected, resolved)) {
      throw new IOException(
          "Maven resolved a different source artifact than requested: " + resolved);
    }
    final Path path = resolved.getFile().toPath().toAbsolutePath().normalize();
    if (!Files.isRegularFile(path)) {
      throw new IOException("Resolved Maven sources artifact is not a regular file: " + path);
    }
    return new MavenSourceClassifierResolver.ResolvedSourceArtifact(
        toCoordinate(candidate, resolved),
        path,
        SourceRepositoryOrigin.identify(result, session, path));
  }

  private static ArtifactCoordinate toCoordinate(
      final ArtifactCoordinate candidate, final Artifact resolved) {
    return new ArtifactCoordinate(
        resolved.getGroupId(),
        resolved.getArtifactId(),
        resolved.getVersion(),
        resolved.getExtension(),
        resolved.getClassifier(),
        candidate.scope());
  }

  private static boolean sameArtifact(final Artifact expected, final Artifact actual) {
    return expected.getGroupId().equals(actual.getGroupId())
        && expected.getArtifactId().equals(actual.getArtifactId())
        && expected.getVersion().equals(actual.getVersion())
        && expected.getExtension().equals(actual.getExtension())
        && expected.getClassifier().equals(actual.getClassifier());
  }
}
