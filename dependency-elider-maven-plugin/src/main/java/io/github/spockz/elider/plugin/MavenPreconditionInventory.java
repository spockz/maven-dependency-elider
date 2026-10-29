/* WHY: Binds precondition evidence and SBOM writers to one post-elision inventory snapshot. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import org.apache.maven.project.MavenProject;

/** Captures the effective retained artifact view and exact proof-inventory state. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenPreconditionInventory {
  private MavenPreconditionInventory() {}

  /** One immutable post-elision inventory shared by assessment and both serializers. */
  record Snapshot(
      List<ArtifactFileRef> artifactFiles,
      PreconditionClassInventory classProviders,
      String rootMembershipFingerprint,
      List<Path> knownOutputs,
      List<Path> knownStages) {
    Snapshot {
      artifactFiles = List.copyOf(artifactFiles);
      Objects.requireNonNull(classProviders, "classProviders");
      Objects.requireNonNull(rootMembershipFingerprint, "rootMembershipFingerprint");
      knownOutputs = MavenPreconditionOutputState.normalizedPaths(knownOutputs);
      knownStages = MavenPreconditionOutputState.normalizedPaths(knownStages);
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    boolean complete() {
      return classProviders.status() == PreconditionClassInventory.Status.COMPLETE;
    }

    /** Rechecks captured roots and rejects provider or target drift. */
    void verifyFresh(
        final MavenProject project,
        final MavenElisionService.ApplyPlan plan,
        final MavenElisionService.Analysis analysis,
        final Collection<Path> actualStages)
        throws IOException {
      verifyFresh(project, plan, analysis, knownOutputs, actualStages);
    }

    /** Rejects target changes as well as provider-root, staging-path, and digest drift. */
    void verifyFresh(
        final MavenProject project,
        final MavenElisionService.ApplyPlan plan,
        final MavenElisionService.Analysis analysis,
        final Collection<Path> actualOutputs,
        final Collection<Path> actualStages)
        throws IOException {
      if (!complete()) {
        return;
      }
      if (!knownOutputs.equals(MavenPreconditionOutputState.normalizedPaths(actualOutputs))) {
        throw new IOException(
            "Precondition generated output targets changed after inventory capture");
      }
      final List<Path> stages = MavenPreconditionOutputState.normalizedPaths(actualStages);
      if (!knownStages.equals(stages)) {
        throw new IOException("Precondition output staging paths changed after inventory capture");
      }
      MavenElisionService.verifyCurrentViews(project, analysis);
      MavenPreconditionStages.validateGenerated(stages);
      final Snapshot current = captureInternal(project, plan, analysis, true, knownOutputs, stages);
      if (!matches(current)) {
        throw new IOException("Precondition provider inventory changed before publication");
      }
    }

    private boolean matches(final Snapshot current) {
      if (!current.complete()
          || !classProviders.fingerprint().equals(current.classProviders().fingerprint())
          || !rootMembershipFingerprint.equals(current.rootMembershipFingerprint())) {
        return false;
      }
      return MavenPreconditionArtifactInventory.identity(artifactFiles)
          .equals(MavenPreconditionArtifactInventory.identity(current.artifactFiles()));
    }
  }

  /** Captures declared providers and retained artifact files. */
  static Snapshot capture(
      final MavenProject project,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final boolean optIn,
      final Collection<Path> knownOutputs)
      throws IOException {
    return captureInternal(project, plan, analysis, optIn, knownOutputs, List.of());
  }

  /** Captures the inventory while binding the transaction's exact staging paths. */
  static Snapshot capture(
      final MavenProject project,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final boolean optIn,
      final Collection<Path> knownOutputs,
      final Collection<Path> knownStages)
      throws IOException {
    return captureInternal(project, plan, analysis, optIn, knownOutputs, knownStages);
  }

  private static Snapshot captureInternal(
      final MavenProject project,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionService.Analysis analysis,
      final boolean optIn,
      final Collection<Path> knownOutputs,
      final Collection<Path> knownStages)
      throws IOException {
    final List<Path> outputs = MavenPreconditionOutputState.normalizedPaths(knownOutputs);
    final List<Path> stages = MavenPreconditionOutputState.normalizedPaths(knownStages);
    final List<ArtifactFileRef> artifactFiles =
        MavenPreconditionArtifactInventory.capture(plan, analysis, false);
    if (!optIn) {
      return incompleteSnapshot(
          artifactFiles,
          "Precondition class-path completeness opt-in is disabled",
          outputs,
          stages);
    }
    try {
      final List<ArtifactFileRef> verifiedArtifactFiles =
          MavenPreconditionArtifactInventory.capture(plan, analysis, true);
      MavenPreconditionStages.validateIfPresent(stages);
      final MavenPreconditionProviderRoots.Capture roots =
          MavenPreconditionProviderRoots.capture(project, analysis, stages);
      final List<Provider> providers =
          new ArrayList<>(
              MavenPreconditionArtifactInventory.dependencyProviders(verifiedArtifactFiles));
      providers.addAll(roots.providers());
      return new Snapshot(
          verifiedArtifactFiles,
          PreconditionClassInventory.complete(providers),
          MavenPreconditionOutputState.fingerprint(
              List.of(roots.fingerprint()),
              MavenPreconditionOutputState.identity(outputs, stages),
              MavenPreconditionOutputState.states(outputs)),
          outputs,
          stages);
    } catch (final IOException
        | UncheckedIOException
        | IllegalArgumentException
        | SecurityException failure) {
      return incompleteSnapshot(
          artifactFiles,
          "Could not capture complete Maven class-provider inventory: " + failure.getMessage(),
          outputs,
          stages);
    }
  }

  private static Snapshot incompleteSnapshot(
      final List<ArtifactFileRef> artifactFiles,
      final String reason,
      final List<Path> outputs,
      final List<Path> stages) {
    return new Snapshot(
        artifactFiles,
        PreconditionClassInventory.incomplete(List.of(), reason),
        MavenPreconditionOutputState.fingerprint(
            List.of(reason), MavenPreconditionOutputState.identity(outputs, stages), List.of()),
        outputs,
        stages);
  }
}
