// WHY: Produces detached coordinates and byte identities from original resolver results.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.eclipse.aether.graph.DependencyNode;

/** Extracts artifact evidence from the exact graph and result used by the audit. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class MavenOriginalInputArtifacts {
  private MavenOriginalInputArtifacts() {}

  static List<MavenOriginalInputAudit.AuditArtifact> resolved(
      final List<org.eclipse.aether.graph.Dependency> dependencies) throws IOException {
    final List<MavenOriginalInputAudit.AuditArtifact> artifacts =
        new ArrayList<>(dependencies.size());
    for (final org.eclipse.aether.graph.Dependency dependency : dependencies) {
      if (dependency == null) {
        throw new IOException("Resolved dependency is missing from the original-input result");
      }
      artifacts.add(auditArtifact(dependency));
    }
    artifacts.sort(Comparator.comparing(MavenOriginalInputAudit.AuditArtifact::coordinate));
    return artifacts;
  }

  static List<ArtifactCoordinate> direct(final DependencyNode graph) throws IOException {
    final List<ArtifactCoordinate> coordinates = new ArrayList<>();
    for (final DependencyNode node : graph.getChildren()) {
      final org.eclipse.aether.graph.Dependency dependency = node.getDependency();
      if (dependency != null) {
        coordinates.add(coordinate(dependency.getArtifact(), dependency.getScope()));
      }
    }
    coordinates.sort(Comparator.naturalOrder());
    return List.copyOf(coordinates);
  }

  private static MavenOriginalInputAudit.AuditArtifact auditArtifact(
      final org.eclipse.aether.graph.Dependency dependency) throws IOException {
    if (dependency.getArtifact() == null) {
      throw new IOException("Resolved original dependency has no artifact");
    }
    final ArtifactCoordinate coordinate =
        coordinate(dependency.getArtifact(), dependency.getScope());
    final String mavenType = mavenType(dependency.getArtifact(), coordinate);
    final Path file = artifactFile(coordinate, mavenType, dependency.getArtifact().getFile());
    if (file == null) {
      return new MavenOriginalInputAudit.AuditArtifact(coordinate, mavenType, null, null);
    }
    return new MavenOriginalInputAudit.AuditArtifact(
        coordinate, mavenType, file.toString(), ArtifactFileDigest.sha256(file));
  }

  private static Path artifactFile(
      final ArtifactCoordinate coordinate, final String mavenType, final java.io.File file)
      throws IOException {
    final boolean supportedProvider =
        "jar".equals(mavenType)
            && "jar".equals(coordinate.type())
            && ("compile".equals(coordinate.scope()) || "runtime".equals(coordinate.scope()));
    if (file == null) {
      requireProviderFile(
          supportedProvider, "Resolved original dependency has no artifact file: " + coordinate);
      return null;
    }
    final Path path = file.toPath().toAbsolutePath().normalize();
    if (Files.isRegularFile(path) && Files.isReadable(path)) {
      return path;
    }
    requireProviderFile(
        supportedProvider, "Resolved original dependency is not a readable file: " + path);
    return null;
  }

  private static void requireProviderFile(final boolean supportedProvider, final String message)
      throws IOException {
    if (supportedProvider) {
      throw new IOException(message);
    }
  }

  /* package */ static String mavenType(
      final org.eclipse.aether.artifact.Artifact artifact, final ArtifactCoordinate coordinate)
      throws IOException {
    final String mavenType = artifact.getProperty("type", artifact.getExtension());
    if (mavenType == null || mavenType.isBlank()) {
      throw new IOException(
          "Resolved original dependency has no Maven artifact type: " + coordinate);
    }
    return mavenType;
  }

  /* package */ static ArtifactCoordinate coordinate(
      final org.eclipse.aether.artifact.Artifact artifact, final String scope) throws IOException {
    if (artifact == null) {
      throw new IOException("Resolver dependency has no artifact");
    }
    if (scope == null || scope.isBlank()) {
      throw new IOException("Resolved original dependency has no effective Maven scope");
    }
    if (artifact.getExtension() == null || artifact.getExtension().isBlank()) {
      throw new IOException("Resolved original dependency has no Resolver extension");
    }
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getExtension(),
        artifact.getClassifier(),
        scope);
  }
}
