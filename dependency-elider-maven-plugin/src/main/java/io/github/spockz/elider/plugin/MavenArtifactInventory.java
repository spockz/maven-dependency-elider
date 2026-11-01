// WHY: Validates Maven artifact snapshots and prepares nonmutating
// artifact-view plans.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ApplyPlan;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CurrentViews;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Validates Maven artifact snapshots and prepares nonmutating artifact-view plans. */
final class MavenArtifactInventory {
  private MavenArtifactInventory() {}

  /* package */ static void verifyPreparedInventory(final PreparedAnalysis prepared)
      throws IOException {
    NativeImageConsumedInput.verifyAll(prepared.dynamicRootInputs().consumedInputs());
    final MavenAnalysisResolutionContext resolutionContext = prepared.resolutionContext();
    if (resolutionContext != null
        && resolutionContext.provenance() == AnalyzePrediction.Provenance.DETACHED_CURRENT_MODEL) {
      resolutionContext.verify();
      return;
    }
    verifyProjectInventory(
        prepared.project(),
        prepared.directArtifactsPresent(),
        prepared.inputFingerprint(),
        prepared.directInputFingerprint());
  }

  /* package */ static void verifyProjectInventory(
      final MavenProject project,
      final boolean directPresent,
      final String expectedResolvedFingerprint,
      final String expectedDirectFingerprint)
      throws IOException {
    final List<ArtifactSnapshot> resolvedSnapshots =
        snapshots(new ArrayList<>(project.getArtifacts()));
    if (!expectedResolvedFingerprint.equals(
        ResolvedArtifactInventoryFingerprint.fingerprint(resolvedSnapshots))) {
      throw new IOException("Live Maven resolved artifact view changed during analysis");
    }
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directViewPresent = directView != null;
    if (directViewPresent != directPresent) {
      throw new IOException("Live Maven direct artifact view presence changed during analysis");
    }
    if (directPresent) {
      final List<ArtifactSnapshot> directSnapshots = snapshots(new ArrayList<>(directView));
      if (!expectedDirectFingerprint.equals(
          ResolvedArtifactInventoryFingerprint.fingerprint(directSnapshots))) {
        throw new IOException("Live Maven direct artifact view changed during analysis");
      }
    }
  }

  /* package */ static ApplyPlan plan(final MavenProject project, final Analysis analysis)
      throws IOException {
    return MavenArtifactPlan.prepare(project, analysis);
  }

  /* package */ static CurrentViews verifyCurrentViews(
      final MavenProject project, final Analysis analysis) throws IOException {
    final List<Artifact> resolvedInput = new ArrayList<>(project.getArtifacts());
    MavenArtifactViewValidation.validateCurrentView(
        "resolved", resolvedInput, analysis.artifacts().resolvedSnapshots());
    final Set<Artifact> directSet = project.getDependencyArtifacts();
    final boolean directViewPresent = directSet != null;
    if (directViewPresent != analysis.artifacts().directArtifactsPresent()) {
      throw new IOException("Maven direct artifact view presence changed after analysis");
    }
    final List<Artifact> directInput = directSet == null ? List.of() : new ArrayList<>(directSet);
    MavenArtifactViewValidation.validateCurrentView(
        "direct", directInput, analysis.artifacts().directSnapshots());
    MavenArtifactPathValidation.validateIdentityPaths(analysis.artifacts().resolvedSnapshots());
    MavenArtifactPathValidation.validateIdentityPaths(analysis.artifacts().directSnapshots());
    MavenArtifactPathValidation.validateDirectPaths(
        analysis.artifacts().resolvedSnapshots(), analysis.artifacts().directSnapshots());
    return new CurrentViews(resolvedInput, directInput);
  }

  /* package */ static List<ArtifactSnapshot> snapshots(final Collection<Artifact> artifacts) {
    return artifacts.stream().map(ArtifactSnapshot::from).toList();
  }

  /* package */ static Path normalizedPath(final Artifact artifact) {
    return normalizedFilePath(artifact.getFile());
  }

  private static Path normalizedFilePath(final File file) {
    return file == null ? null : file.toPath().toAbsolutePath().normalize();
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
}
