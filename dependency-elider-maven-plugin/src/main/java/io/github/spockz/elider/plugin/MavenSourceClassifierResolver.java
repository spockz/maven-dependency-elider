// WHY: Resolves one exact sources classifier through Maven without treating its coordinate as
// proof.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

/** Resolves the exact-version Maven sources classifier for correspondence checks. */
final class MavenSourceClassifierResolver {
  /** Maven Resolver used only to retrieve the exact source classifier. */
  private final RepositorySystem repositorySystem;

  /* default */ MavenSourceClassifierResolver(final RepositorySystem repositorySystem) {
    this.repositorySystem = Objects.requireNonNull(repositorySystem, "repositorySystem");
  }

  /* default */ ResolvedSourceArtifact resolve(
      final ArtifactCoordinate candidate, final MavenProject project, final MavenSession session)
      throws IOException {
    validateInputs(candidate, project, session);
    final Artifact expected = expectedArtifact(candidate);
    final ArtifactResult result =
        resolveArtifact(session.getRepositorySession(), request(expected, project));
    return convertResult(candidate, expected, result);
  }

  private static void validateInputs(
      final ArtifactCoordinate candidate, final MavenProject project, final MavenSession session)
      throws IOException {
    if (candidate == null || candidate.version() == null || candidate.version().isBlank()) {
      throw new IOException("An exact candidate version is required to resolve sources");
    }
    if (project == null || session == null || session.getRepositorySession() == null) {
      throw new IOException("Maven project and resolver session are required to resolve sources");
    }
  }

  private static Artifact expectedArtifact(final ArtifactCoordinate candidate) {
    return new DefaultArtifact(
        candidate.groupId(), candidate.artifactId(), "sources", "jar", candidate.version());
  }

  private static ArtifactRequest request(final Artifact expected, final MavenProject project) {
    return new ArtifactRequest()
        .setArtifact(expected)
        .setRepositories(project.getRemoteProjectRepositories());
  }

  private ArtifactResult resolveArtifact(
      final RepositorySystemSession session, final ArtifactRequest request) throws IOException {
    try {
      return repositorySystem.resolveArtifact(session, request);
    } catch (final org.eclipse.aether.resolution.ArtifactResolutionException exception) {
      throw new IOException("Could not resolve exact Maven sources artifact", exception);
    }
  }

  @SuppressWarnings("PMD.LawOfDemeter") // Aether artifact properties define this exact result.
  private static ResolvedSourceArtifact convertResult(
      final ArtifactCoordinate candidate, final Artifact expected, final ArtifactResult result)
      throws IOException {
    final Artifact resolved = result.getArtifact();
    if (resolved == null || resolved.getFile() == null || !result.isResolved()) {
      throw new IOException("Maven did not resolve the exact sources artifact " + expected);
    }
    if (!sameArtifact(expected, resolved)) {
      throw new IOException(
          "Maven resolved a different source artifact than requested: " + resolved);
    }
    final Path path = resolvedFile(resolved);
    if (!Files.isRegularFile(path)) {
      throw new IOException("Resolved Maven sources artifact is not a regular file: " + path);
    }
    return new ResolvedSourceArtifact(
        toCoordinate(candidate, resolved), path, repositoryId(result));
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

  @SuppressWarnings("PMD.LawOfDemeter") // Maven Resolver exposes the resolved file on Artifact.
  private static Path resolvedFile(final Artifact resolved) {
    return resolved.getFile().toPath().toAbsolutePath().normalize();
  }

  @SuppressWarnings("PMD.LawOfDemeter") // Repository id is metadata returned by Maven Resolver.
  private static String repositoryId(final ArtifactResult result) {
    final ArtifactRepository repository = result.getRepository();
    return repository == null ? "local-or-unspecified" : repository.getId();
  }

  private static boolean sameArtifact(final Artifact expected, final Artifact actual) {
    return expected.getGroupId().equals(actual.getGroupId())
        && expected.getArtifactId().equals(actual.getArtifactId())
        && expected.getVersion().equals(actual.getVersion())
        && expected.getExtension().equals(actual.getExtension())
        && expected.getClassifier().equals(actual.getClassifier());
  }

  /** Result of resolving one exact source classifier. */
  /* default */ record ResolvedSourceArtifact(
      ArtifactCoordinate coordinate, Path path, String repositoryId) {
    /* default */ ResolvedSourceArtifact {
      Objects.requireNonNull(coordinate, "coordinate");
      Objects.requireNonNull(path, "path");
      if (repositoryId == null || repositoryId.isBlank()) {
        throw new IllegalArgumentException("repositoryId must be nonblank");
      }
    }
  }
}
