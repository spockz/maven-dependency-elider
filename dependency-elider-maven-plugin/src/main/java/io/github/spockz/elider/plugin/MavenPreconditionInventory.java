/*
 * WHY: Captures the retained dependency and compiled application providers used for
 * prerequisite proof.
 */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionProof;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Captures the effective retained artifact view and exact proof-inventory state. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPreconditionInventory {
  private record ProofInventoryState(
      Optional<PreconditionProof.InventoryPair> pair, Optional<String> failure) {}

  private MavenPreconditionInventory() {}

  record Snapshot(
      List<ArtifactFileRef> artifactFiles,
      PreconditionClassInventory classProviders,
      boolean optInEnabled,
      Optional<PreconditionProof.InventoryPair> proofInventoryPair,
      Optional<String> proofInventoryFailure) {
    Snapshot {
      artifactFiles = List.copyOf(artifactFiles);
      Objects.requireNonNull(classProviders, "classProviders");
      proofInventoryPair = Objects.requireNonNull(proofInventoryPair, "proofInventoryPair");
      proofInventoryFailure =
          Objects.requireNonNull(proofInventoryFailure, "proofInventoryFailure");
      if (proofInventoryPair.isPresent() && proofInventoryFailure.isPresent()) {
        throw new IllegalArgumentException("Proof inventory cannot be both available and refused");
      }
      if (proofInventoryPair.isPresent()
          && classProviders.status() != PreconditionClassInventory.Status.COMPLETE) {
        throw new IllegalArgumentException(
            "Proof inventory pair requires complete final providers");
      }
    }

    Snapshot(
        final List<ArtifactFileRef> artifactFiles,
        final PreconditionClassInventory classProviders,
        final boolean optInEnabled) {
      this(artifactFiles, classProviders, optInEnabled, Optional.empty(), Optional.empty());
    }

    Snapshot(
        final List<ArtifactFileRef> artifactFiles,
        final PreconditionClassInventory classProviders,
        final boolean optInEnabled,
        final Optional<PreconditionProof.InventoryPair> proofInventoryPair) {
      this(artifactFiles, classProviders, optInEnabled, proofInventoryPair, Optional.empty());
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
          MavenPreconditionProviderRoots.capture(project, session, analysis.evidence(), optIn);
      final List<Provider> finalProviders =
          new ArrayList<>(
              MavenPreconditionArtifactInventory.dependencyProviders(verifiedArtifactFiles));
      finalProviders.addAll(roots.providers());
      final PreconditionClassInventory finalInventory =
          PreconditionClassInventory.complete(finalProviders);
      final PreconditionClassInventory baselineInventory =
          captureBaselineProviders(plan, roots.providers());
      final ProofInventoryState proofState =
          inspectProofInventory(baselineInventory, finalInventory);
      return new Snapshot(
          verifiedArtifactFiles, finalInventory, true, proofState.pair(), proofState.failure());
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

  private static ProofInventoryState inspectProofInventory(
      final PreconditionClassInventory baselineInventory,
      final PreconditionClassInventory finalInventory) {
    try {
      return new ProofInventoryState(
          Optional.of(PreconditionProof.inspectPair(baselineInventory, finalInventory)),
          Optional.empty());
    } catch (final IOException | IllegalArgumentException refusal) {
      return new ProofInventoryState(
          Optional.empty(),
          Optional.of(
              "Could not inspect complete Maven class-provider inventory for proof: "
                  + refusal.getMessage()));
    }
  }

  private static PreconditionClassInventory captureBaselineProviders(
      final ElisionAnalysisModel.ApplyPlan plan, final List<Provider> applicationProviders) {
    try {
      final List<Provider> providers =
          new ArrayList<>(
              MavenPreconditionArtifactInventory.dependencyProviders(
                  MavenPreconditionArtifactInventory.captureOriginal(plan, true)));
      providers.addAll(applicationProviders);
      return PreconditionClassInventory.complete(providers);
    } catch (final IOException | IllegalArgumentException | SecurityException failure) {
      return PreconditionClassInventory.incomplete(
          List.of(),
          "Could not capture complete original Maven class-provider inventory: "
              + failure.getMessage());
    }
  }

  private static Snapshot incompleteSnapshot(
      final List<ArtifactFileRef> artifactFiles, final String reason, final boolean optInEnabled) {
    return new Snapshot(
        artifactFiles,
        PreconditionClassInventory.incomplete(List.of(), reason),
        optInEnabled,
        Optional.empty(),
        Optional.empty());
  }
}
