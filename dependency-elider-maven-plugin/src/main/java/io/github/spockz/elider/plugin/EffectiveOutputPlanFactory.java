/* WHY: Builds the immutable plan shared by Analyze prediction and Elide output staging. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Keeps Analyze and Elide on one output eligibility plan. */
final class EffectiveOutputPlanFactory {
  private EffectiveOutputPlanFactory() {}

  /* package */ static TrimGenerationPublisher.EffectiveOutputPlan create(
      final ElisionAnalysisModel.EffectiveAnalysis effective) throws IOException {
    final ElisionAnalysisModel.PreparedAnalysis prepared = effective.prepared();
    final ElisionAnalysisModel.AnalysisOptions options = prepared.options();
    final Map<TrimArtifactRootKey, Set<String>> roots =
        TrimRootPlanner.artifactRootKeys(
            prepared.resolvedSnapshots(), effective.trimAnalysis().candidateRoots());
    final Set<ArtifactCoordinate> unchangedCoordinates =
        new LinkedHashSet<>(effective.forcedUnchangedCoordinates());
    unchangedCoordinates.addAll(effective.trimAnalysis().forcedUnchangedCoordinates());
    final Set<Path> serviceDescriptorOwners =
        prepared.dynamicRootInputs().scansByPath().entrySet().stream()
            .filter(entry -> !entry.getValue().serviceDescriptors().isEmpty())
            .map(Map.Entry::getKey)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    unchangedCoordinates.addAll(
        classlessRetainedCoordinates(
            prepared.resolvedSnapshots(),
            prepared.index().classesByArtifact(),
            effective.effectiveDecision().retainedArtifacts(),
            serviceDescriptorOwners));
    return new TrimGenerationPublisher.EffectiveOutputPlan(
        prepared,
        effective.trimAnalysis(),
        roots,
        unchangedCoordinates,
        effective.effectiveDecision().retainedArtifacts(),
        effective.inventoryFingerprint(),
        prepared.directInputFingerprint(),
        effective.operationFingerprint(),
        prepared.productionOutputFingerprint(),
        prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
        options.trim().explicitRoots(),
        options.trim().passThroughArtifacts(),
        options.completeness().sourceRootsComplete(),
        options.completeness().productionClassesComplete(),
        options.trim().mrjarStrategy(),
        options.trim().failOnUnsupportedModuleInfo());
  }

  private static Set<ArtifactCoordinate> classlessRetainedCoordinates(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final Map<ArtifactFileRef, Set<String>> classesByArtifact,
      final Set<ArtifactCoordinate> retained,
      final Set<Path> serviceDescriptorOwners) {
    final Map<Path, Set<String>> byPath = TrimCandidatePlanner.classesByPath(classesByArtifact);
    return inventory.stream()
        .filter(snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
        .filter(snapshot -> retained.contains(snapshot.coordinate()))
        .filter(
            snapshot ->
                byPath
                    .getOrDefault(snapshot.filePath().toAbsolutePath().normalize(), Set.of())
                    .isEmpty())
        .filter(
            snapshot ->
                !serviceDescriptorOwners.contains(snapshot.filePath().toAbsolutePath().normalize()))
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }
}
