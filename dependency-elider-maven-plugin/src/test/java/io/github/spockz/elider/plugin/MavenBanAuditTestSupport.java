// WHY: Shares the minimal graph and artifact fixtures used to prove original-audit boundaries.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Map;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;

/** Builds Maven and Resolver inputs for audit-context tests. */
final class MavenBanAuditTestSupport {
  /** Fixture Maven group used in graph and coordinate rows. */
  private static final String GROUP = "fixture";

  /** Fixture Maven version used to keep graph identity stable. */
  private static final String VERSION = "1.0";

  /** Resolver scope used by every test artifact. */
  private static final String SCOPE = "compile";

  /** File extension and Maven type used by fixture artifacts. */
  private static final String JAR_TYPE = "jar";

  private MavenBanAuditTestSupport() {
    throw new AssertionError("No instances");
  }

  /* default */ static MavenProject project(final Path temporaryDirectory) throws IOException {
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP);
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.setFile(Files.createFile(temporaryDirectory.resolve("pom.xml")).toFile());
    return project;
  }

  /* default */ static DependencyNode root() {
    return new DefaultDependencyNode(new DefaultArtifact(GROUP, "consumer", "", "pom", VERSION));
  }

  /* default */ static DefaultDependencyNode node(final String artifactId, final Path path) {
    final DefaultArtifact artifact =
        new DefaultArtifact(GROUP, artifactId, "", JAR_TYPE, VERSION, Map.of(), path.toFile());
    return new DefaultDependencyNode(new Dependency(artifact, SCOPE));
  }

  /* default */ static Artifact mavenArtifact(final String artifactId, final Path path) {
    final Artifact artifact =
        org.apache.maven.RepositoryUtils.toArtifact(
            new DefaultArtifact(GROUP, artifactId, "", JAR_TYPE, VERSION, Map.of(), path.toFile()));
    artifact.setScope(SCOPE);
    return artifact;
  }

  /* default */ static MavenOriginalInputAudit.AuditArtifact auditArtifact(
      final String artifactId, final Path path) throws IOException {
    return new MavenOriginalInputAudit.AuditArtifact(
        coordinate(artifactId),
        JAR_TYPE,
        path.toAbsolutePath().normalize().toString(),
        java.util.HexFormat.of().formatHex(sha256(path)));
  }

  /* default */ static ArtifactCoordinate coordinate(final String artifactId) {
    return new ArtifactCoordinate(GROUP, artifactId, VERSION, JAR_TYPE, "", SCOPE);
  }

  /* default */ static ResolverArtifactGraphCapturePair graphPair(
      final String projectKey, final DependencyNode root) {
    final ResolverArtifactGraphSnapshot before =
        ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L);
    final ResolverArtifactGraphSnapshot after =
        ResolverArtifactGraphSnapshot.capture(root, projectKey, false, null, 0L, 1L);
    return new ResolverArtifactGraphCapturePair(
        projectKey, "fixture-capture", 1L, false, null, 0L, before, after);
  }

  private static byte[] sha256(final Path path) throws IOException {
    try {
      return MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path));
    } catch (final java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
