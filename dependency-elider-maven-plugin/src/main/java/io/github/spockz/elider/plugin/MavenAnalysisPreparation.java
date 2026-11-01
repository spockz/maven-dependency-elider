// WHY: Prepares a checked raw elision plan through explicit inventory,
// evidence, and graph stages.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactViews;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Prepares a checked raw plan before any trimming or artifact publication. */
final class MavenAnalysisPreparation {
  private MavenAnalysisPreparation() {}

  /* default */ static PreparedAnalysis prepare(
      final MavenProject project, final AnalysisOptions options, final DynamicRootScanner scanner)
      throws IOException, MojoFailureException {
    verifyCompleteness(options.completeness());
    final Inventory inventory = inventory(project);
    final BanishedDependencyPolicy.Resolution banResolution =
        BanishedDependencyPolicy.resolve(
            options.retainedArtifacts(),
            options.banishedDependencies(),
            options.trim().passThroughArtifacts(),
            inventory.views().resolvedSnapshots(),
            inventory.views().directSnapshots());
    if (!banResolution.requested().isEmpty()) {
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
    final MavenAnalysisEvidence.RootEvidence evidence =
        MavenAnalysisEvidence.scan(project, options, inventory.candidates(), scanner);
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
    verifyInventory(project, inventory);
    final ElisionDecision decision =
        rawDecision(options, inventory, evidence, keep, requiredClasses);
    final MavenElisionGraphBinding.Result graphBinding =
        MavenElisionGraphBinding.bind(
            project,
            options,
            inventory.views().resolvedSnapshots(),
            decision,
            evidence.trace(),
            requiredClasses,
            evidence.dynamicRoots().consumedInputs());
    verifyGraphBinding(project, inventory, graphBinding);
    NativeImageConsumedInput.verifyAll(evidence.dynamicRoots().consumedInputs());
    return new PreparedAnalysis(
        project,
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
        evidence.sourceAttributionFallback());
  }

  private static void verifyCompleteness(final CompletenessOptions completeness)
      throws IOException {
    if (completeness.sourceRootsComplete() && completeness.productionClassesComplete()) {
      throw new IOException(
          "elide.sourceRootsComplete=true and "
              + "elide.productionClassesComplete=true are mutually exclusive");
    }
  }

  private static Inventory inventory(final MavenProject project) throws IOException {
    final List<ArtifactSnapshot> resolved =
        MavenArtifactInventory.snapshots(new ArrayList<>(project.getArtifacts()));
    MavenArtifactPathValidation.validateIdentityPaths(resolved);
    final String resolvedFingerprint = ResolvedArtifactInventoryFingerprint.fingerprint(resolved);
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    final List<ArtifactSnapshot> direct =
        MavenArtifactInventory.snapshots(directPresent ? new ArrayList<>(directView) : List.of());
    MavenArtifactPathValidation.validateIdentityPaths(direct);
    final String directFingerprint =
        directPresent ? ResolvedArtifactInventoryFingerprint.fingerprint(direct) : "missing";
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (final ArtifactSnapshot snapshot : resolved) {
      if (MavenArtifactInventory.isJarCandidate(snapshot)) {
        candidates.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
    }
    return new Inventory(
        new ArtifactViews(resolved, directPresent, direct),
        resolvedFingerprint,
        directFingerprint,
        candidates);
  }

  private static Set<ArtifactCoordinate> keepArtifacts(
      final AnalysisOptions options,
      final Inventory inventory,
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
      final Inventory inventory,
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

  private static void verifyInventory(final MavenProject project, final Inventory inventory)
      throws IOException {
    final ArtifactViews views = inventory.views();
    MavenArtifactInventory.verifyProjectInventory(
        project,
        views.directArtifactsPresent(),
        inventory.resolvedFingerprint(),
        inventory.directFingerprint());
    MavenElisionGraphBinding.verifyInventoryFingerprint(
        views.resolvedSnapshots(), inventory.resolvedFingerprint());
  }

  private static void verifyGraphBinding(
      final MavenProject project,
      final Inventory inventory,
      final MavenElisionGraphBinding.Result graphBinding)
      throws IOException {
    MavenElisionGraphBinding.verifyInventoryFingerprint(
        inventory.views().resolvedSnapshots(), graphBinding.inventoryFingerprint());
    if (!inventory.resolvedFingerprint().equals(graphBinding.inventoryFingerprint())) {
      throw new IOException("Resolved artifact inventory changed during analysis preparation");
    }
    final ArtifactViews views = inventory.views();
    MavenArtifactInventory.verifyProjectInventory(
        project,
        views.directArtifactsPresent(),
        inventory.resolvedFingerprint(),
        inventory.directFingerprint());
  }

  private record Inventory(
      ArtifactViews views,
      String resolvedFingerprint,
      String directFingerprint,
      List<ArtifactFileRef> candidates) {}
}
