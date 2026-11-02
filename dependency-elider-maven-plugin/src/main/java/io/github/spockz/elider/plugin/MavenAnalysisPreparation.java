// WHY: Prepares a checked raw elision plan through explicit inventory,
// evidence, and graph stages.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Prepares a checked raw plan before any trimming or artifact publication. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class MavenAnalysisPreparation {
  private MavenAnalysisPreparation() {}

  /* default */ static PreparedAnalysis prepare(
      final MavenProject project, final AnalysisOptions options, final DynamicRootScanner scanner)
      throws IOException, MojoFailureException {
    return prepare(project, options, scanner, null);
  }

  /* default */ static PreparedAnalysis prepare(
      final MavenProject project,
      final AnalysisOptions requestedOptions,
      final DynamicRootScanner scanner,
      final MavenAnalysisResolutionContext resolutionContext)
      throws IOException, MojoFailureException {
    final AnalysisOptions options =
        resolutionContext == null
            ? requestedOptions
            : requestedOptions.withEnvironment(resolutionContext.environment());
    verifyCompleteness(options.completeness());
    final MavenProject analysisProject =
        resolutionContext == null ? project : resolutionContext.project();
    final MavenAnalysisInventory.Snapshot inventory =
        resolutionContext == null
            ? MavenAnalysisInventory.capture(project)
            : MavenAnalysisInventory.capture(resolutionContext);
    rejectRequestedBans(analysisProject, options, inventory.views());
    final MavenAnalysisEvidence.RootEvidence evidence =
        MavenAnalysisEvidence.scan(analysisProject, options, inventory.candidates(), scanner);
    final MavenElisionPolicyIdentity.Options policyOptions =
        MavenElisionPolicyIdentity.normalize(options);
    final Set<String> requiredClasses =
        DynamicRootOrchestrator.requiredClassesForTrimming(
            evidence.sourceRequiredClasses(),
            evidence.dynamicRoots().classNames(),
            options.trim().explicitRoots(),
            evidence.index(),
            options.trim().enabled());
    final Set<ArtifactCoordinate> keep = keepArtifacts(options, inventory, evidence);
    final Set<String> projectOutputClasses =
        MavenAnalysisEvidence.projectOutputClasses(
            evidence.declaredClasses(), evidence.productionOutputClasses());
    final ClassUsageReport classUsageReport =
        ClassUsageReport.classify(evidence.index(), evidence.trace(), evidence.bytecodeScan());
    NativeImageConsumedInput.verifyAll(evidence.dynamicRoots().consumedInputs());
    MavenAnalysisInventory.verifyInventory(project, inventory, resolutionContext);
    final ElisionDecision decision =
        rawDecision(options, inventory, evidence, keep, requiredClasses);
    final MavenElisionGraphBinding.Result graphBinding =
        resolutionContext == null
            ? MavenElisionGraphBinding.bind(
                analysisProject,
                options,
                inventory.views().resolvedSnapshots(),
                decision,
                evidence.trace(),
                requiredClasses,
                evidence.dynamicRoots().consumedInputs(),
                policyOptions)
            : MavenElisionGraphBinding.bind(
                analysisProject,
                options,
                resolutionContext,
                decision,
                evidence.trace(),
                requiredClasses,
                evidence.dynamicRoots().consumedInputs(),
                policyOptions);
    MavenAnalysisInventory.verifyGraphBinding(project, inventory, graphBinding, resolutionContext);
    NativeImageConsumedInput.verifyAll(evidence.dynamicRoots().consumedInputs());
    return new PreparedAnalysis(
        analysisProject,
        options,
        inventory.views().resolvedSnapshots(),
        inventory.views().directArtifactsPresent(),
        inventory.views().directSnapshots(),
        decision,
        classUsageReport,
        evidence.bytecodeScan(),
        inventory.candidates(),
        evidence.trace(),
        evidence.index(),
        evidence.dynamicRoots(),
        projectOutputClasses,
        evidence.sourceRequiredClasses(),
        requiredClasses,
        evidence.productionOutputFingerprint(),
        inventory.resolvedFingerprint(),
        inventory.directFingerprint(),
        graphBinding,
        policyOptions,
        evidence.sourceAttributionFallback(),
        resolutionContext);
  }

  /* default */ static void rejectRequestedBans(
      final MavenProject project, final AnalysisOptions options, final ArtifactViews views)
      throws MojoFailureException {
    final BanishedDependencyPolicy.Resolution banResolution =
        BanishedDependencyPolicy.resolve(
            options.retainedArtifacts(),
            options.banishedDependencies(),
            project.getDependencies(),
            options.trim().passThroughArtifacts(),
            views.resolvedSnapshots(),
            views.directSnapshots());
    if (banResolution.requested().isEmpty()) {
      return;
    }
    final List<BanishedDependency> currentMatches =
        banResolution.matches().stream()
            .filter(BanishedDependencyPolicy.Match::matched)
            .map(BanishedDependencyPolicy.Match::dependency)
            .toList();
    throw new MojoFailureException(
        "elide.banishedDependencies cannot be applied because strict ban enforcement is not "
            + "available for this operation; the operation fails closed. Current inventory "
            + "matches: "
            + currentMatches
            + "; no current inventory match: "
            + banResolution.noCurrentInventoryMatch());
  }

  /* default */ static void rejectBanRequestBeforePrediction(final List<String> configuredBans)
      throws MojoFailureException {
    final List<BanishedDependency> requested;
    try {
      requested = BanishedDependencyPolicy.normalize(configuredBans);
    } catch (final IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Invalid elide.banishedDependencies configuration: " + exception.getMessage(), exception);
    }
    if (!requested.isEmpty()) {
      throw new MojoFailureException(
          "elide.banishedDependencies cannot be applied because strict ban enforcement is not "
              + "available for this operation; the operation fails closed before prediction.");
    }
  }

  private static void verifyCompleteness(final CompletenessOptions completeness)
      throws IOException {
    if (completeness.sourceRootsComplete() && completeness.productionClassesComplete()) {
      throw new IOException(
          "elide.sourceRootsComplete=true and "
              + "elide.productionClassesComplete=true are mutually exclusive");
    }
  }

  private static Set<ArtifactCoordinate> keepArtifacts(
      final AnalysisOptions options,
      final MavenAnalysisInventory.Snapshot inventory,
      final MavenAnalysisEvidence.RootEvidence evidence)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> keep = new HashSet<>(evidence.compileVisibleCoordinates());
    final DynamicRootInputs roots = evidence.dynamicRoots();
    keep.addAll(roots.declaringArtifacts());
    keep.addAll(roots.resourceProviderArtifacts());
    keep.addAll(
        DynamicRootOrchestrator.dynamicRootArtifactOwners(
            roots, evidence.index(), inventory.candidates()));
    if (options.trim().enabled()) {
      keep.addAll(
          ElisionArtifactPolicy.parsePassThroughCoordinates(
              options.trim().passThroughArtifacts(), inventory.views().resolvedSnapshots()));
    }
    return keep;
  }

  private static ElisionDecision rawDecision(
      final AnalysisOptions options,
      final MavenAnalysisInventory.Snapshot inventory,
      final MavenAnalysisEvidence.RootEvidence evidence,
      final Set<ArtifactCoordinate> keep,
      final Set<String> requiredClasses)
      throws MojoFailureException {
    final ElisionDecision jars =
        new DependencyPruner()
            .prune(
                inventory.candidates(),
                evidence.index(),
                evidence.trace(),
                ElisionArtifactPolicy.config(options.retainedArtifacts(), keep),
                requiredClasses);
    return ElisionArtifactPolicy.retainNonJarArtifacts(jars, inventory.views().resolvedSnapshots());
  }
}
