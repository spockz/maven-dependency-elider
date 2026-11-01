// WHY: Resolves one exact sources classifier through Maven without treating its coordinate as
// proof.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
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
    final RepositorySystemSession repositorySession = isolatedSession(session);
    final ArtifactResult result = resolveArtifact(repositorySession, request(expected, project));
    return MavenSourceArtifactResult.convert(candidate, expected, result, repositorySession);
  }

  private static RepositorySystemSession isolatedSession(final MavenSession session) {
    return new DefaultRepositorySystemSession(session.getRepositorySession())
        .setWorkspaceReader(null);
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

  /** Result of resolving one exact source classifier. */
  /* default */ record ResolvedSourceArtifact(
      ArtifactCoordinate coordinate, Path path, String repositoryProvenance) {
    /* default */ ResolvedSourceArtifact {
      Objects.requireNonNull(coordinate, "coordinate");
      Objects.requireNonNull(path, "path");
      if (repositoryProvenance == null || repositoryProvenance.isBlank()) {
        throw new IllegalArgumentException("repositoryProvenance must be nonblank");
      }
    }
  }
}
