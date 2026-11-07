/*
 * WHY: Captures the retained dependency and compiled application providers used for
 * prerequisite proof.
 */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Captures the effective retained artifact view and exact proof-inventory state. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPreconditionInventory {
  private MavenPreconditionInventory() {}

  record Snapshot(
      List<ArtifactFileRef> artifactFiles,
      PreconditionClassInventory classProviders,
      boolean optInEnabled) {
    Snapshot {
      artifactFiles = List.copyOf(artifactFiles);
      Objects.requireNonNull(classProviders, "classProviders");
    }

    boolean complete() {
      return optInEnabled && classProviders.status() == PreconditionClassInventory.Status.COMPLETE;
    }
  }

  static Snapshot capture(
      final MavenProject project,
      final ElisionAnalysisModel.ApplyPlan plan,
      final ElisionAnalysisModel.Analysis analysis,
      final boolean optIn)
      throws IOException {
    return captureInternal(project, null, plan, analysis, optIn);
  }

  static Snapshot capture(
      final MavenProject project,
      final MavenSession session,
      final ElisionAnalysisModel.ApplyPlan plan,
      final ElisionAnalysisModel.Analysis analysis,
      final boolean optIn)
      throws IOException {
    return captureInternal(project, session, plan, analysis, optIn);
  }

  private static Snapshot captureInternal(
      final MavenProject project,
      final MavenSession session,
      final ElisionAnalysisModel.ApplyPlan plan,
      final ElisionAnalysisModel.Analysis analysis,
      final boolean optIn)
      throws IOException {
    if (!optIn) {
      return incompleteSnapshot(
          MavenPreconditionArtifactInventory.capture(plan, analysis, false),
          "Precondition class-path completeness opt-in is disabled",
          false);
    }
    try {
      MavenCompilerGenerationGuard.requireSafeCompilerConfiguration(
          project, session, analysis.evidence().trustedProcessClassesContext());
      final List<ArtifactFileRef> verifiedArtifactFiles =
          MavenPreconditionArtifactInventory.capture(plan, analysis, true);
      final MavenPreconditionProviderRoots.Capture roots =
          MavenPreconditionProviderRoots.capture(project, session, analysis);
      final List<Provider> providers =
          new ArrayList<>(
              MavenPreconditionArtifactInventory.dependencyProviders(verifiedArtifactFiles));
      providers.addAll(roots.providers());
      return new Snapshot(
          verifiedArtifactFiles, PreconditionClassInventory.complete(providers), true);
    } catch (final IOException
        | UncheckedIOException
        | IllegalArgumentException
        | SecurityException failure) {
      return incompleteSnapshot(
          MavenPreconditionArtifactInventory.capture(plan, analysis, false),
          "Could not capture complete Maven class-provider inventory: " + failure.getMessage(),
          true);
    }
  }

  private static Snapshot incompleteSnapshot(
      final List<ArtifactFileRef> artifactFiles, final String reason, final boolean optInEnabled) {
    return new Snapshot(
        artifactFiles, PreconditionClassInventory.incomplete(List.of(), reason), optInEnabled);
  }
}
