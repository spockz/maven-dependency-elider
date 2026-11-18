// WHY: Validates Maven artifact snapshots and prepares nonmutating
// artifact-view plans.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ApplyPlan;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Validates Maven artifact snapshots and prepares nonmutating artifact-view plans. */
final class MavenArtifactInventory {
  private MavenArtifactInventory() {}

  /* package */ static ApplyPlan plan(final MavenProject project, final Analysis analysis)
      throws IOException {
    return MavenArtifactPlan.prepare(project, analysis);
  }

  /* package */ static List<ArtifactSnapshot> snapshots(final Collection<Artifact> artifacts) {
    return artifacts.stream().map(ArtifactSnapshot::from).toList();
  }

  /* package */ static Path normalizedPath(final Artifact artifact) {
    return normalizedFilePath(artifact.getFile());
  }

  private static Path normalizedFilePath(final File file) {
    if (file == null) {
      return null;
    }
    final Path normalized = file.toPath().toAbsolutePath().normalize();
    try {
      return Files.exists(normalized) ? normalized.toRealPath() : normalized;
    } catch (final IOException ignored) {
      return normalized;
    }
  }

  /* package */ static boolean isJarCandidate(final ArtifactSnapshot snapshot) throws IOException {
    if (!"jar".equals(snapshot.coordinate().type())) {
      return false;
    }
    final Path file = snapshot.filePath();
    if (file == null) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    final Path fileName = file.getFileName();
    if (fileName == null || !Files.isRegularFile(file)) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    return fileName.toString().endsWith(".jar");
  }

  /* package */ static boolean isJarCandidate(final Artifact artifact) throws IOException {
    return isJarCandidate(ArtifactSnapshot.from(artifact));
  }

  /* package */ static ArtifactCoordinate toCoordinate(final Artifact artifact) {
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getType(),
        artifact.getClassifier(),
        artifact.getScope());
  }

  /* package */ static boolean isTestScoped(final Artifact artifact) {
    return Artifact.SCOPE_TEST.equals(artifact.getScope());
  }

  /* package */ static boolean isTestScoped(final ArtifactCoordinate coordinate) {
    return Artifact.SCOPE_TEST.equals(coordinate.scope());
  }
}
