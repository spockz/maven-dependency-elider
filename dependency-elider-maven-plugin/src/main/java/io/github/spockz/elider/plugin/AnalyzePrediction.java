// WHY: Separates Analyze's in-memory prediction from trim output records and publication state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisEvidence;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Holds the dependency decision and provenance reported by Analyze. */
record AnalyzePrediction(
    Provenance provenance,
    List<ArtifactSnapshot> inputArtifacts,
    List<ArtifactCoordinate> retainedArtifacts,
    List<ArtifactCoordinate> wouldElideArtifacts,
    List<PlannedTrim> plannedTrims,
    AnalysisEvidence evidence,
    String environmentFingerprint,
    String inventoryFingerprint,
    String operationFingerprint,
    AnalyzeBanPlan banPlan) {
  /* default */ AnalyzePrediction(
      final Provenance provenance,
      final List<ArtifactSnapshot> inputArtifacts,
      final List<ArtifactCoordinate> retainedArtifacts,
      final List<ArtifactCoordinate> wouldElideArtifacts,
      final List<PlannedTrim> plannedTrims,
      final AnalysisEvidence evidence,
      final String environmentFingerprint,
      final String inventoryFingerprint,
      final String operationFingerprint) {
    this(
        provenance,
        inputArtifacts,
        retainedArtifacts,
        wouldElideArtifacts,
        plannedTrims,
        evidence,
        environmentFingerprint,
        inventoryFingerprint,
        operationFingerprint,
        AnalyzeBanPlan.empty());
  }

  AnalyzePrediction {
    Objects.requireNonNull(provenance, "provenance");
    inputArtifacts = List.copyOf(inputArtifacts);
    retainedArtifacts = retainedArtifacts.stream().sorted().toList();
    wouldElideArtifacts = wouldElideArtifacts.stream().sorted().toList();
    plannedTrims = plannedTrims.stream().sorted().toList();
    Objects.requireNonNull(evidence, "evidence");
    Objects.requireNonNull(environmentFingerprint, "environmentFingerprint");
    Objects.requireNonNull(inventoryFingerprint, "inventoryFingerprint");
    Objects.requireNonNull(operationFingerprint, "operationFingerprint");
    Objects.requireNonNull(banPlan, "banPlan");
  }

  /* default */ static AnalyzePrediction from(final ElisionAnalysisModel.EffectiveAnalysis analysis)
      throws IOException {
    return new AnalyzePrediction(
        analysis.prepared().resolutionContext().provenance(),
        analysis.prepared().resolvedSnapshots(),
        List.copyOf(analysis.effectiveDecision().retainedArtifacts()),
        List.copyOf(analysis.effectiveDecision().elidedArtifacts()),
        plannedTrims(analysis),
        ElisionAnalysisModel.evidence(analysis.prepared()),
        analysis.prepared().resolutionContext().environment().fingerprint(),
        analysis.inventoryFingerprint(),
        analysis.operationFingerprint(),
        analysis.banPlan());
  }

  private static List<PlannedTrim> plannedTrims(
      final ElisionAnalysisModel.EffectiveAnalysis analysis) throws IOException {
    final List<PlannedTrim> planned = new java.util.ArrayList<>();
    for (final Map.Entry<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> entry :
        analysis.trimAnalysis().candidateAnalyses().entrySet()) {
      final ArtifactCoordinate coordinate = entry.getKey();
      if (!analysis.effectiveDecision().retainedArtifacts().contains(coordinate)
          || analysis.forcedUnchangedCoordinates().contains(coordinate)) {
        continue;
      }
      final ArtifactSnapshot artifact = inputArtifact(analysis, coordinate);
      if (analysis.prepared().options().trim().enabled()
          && MavenDependencyTrimmer.MRJAR_PASS_THROUGH.equals(
              analysis.prepared().options().trim().mrjarStrategy())
          && MultiReleaseClassInventory.hasUnsupportedVersionedClasses(artifact.filePath())) {
        continue;
      }
      final Set<String> inputClasses =
          analysis.prepared().index().classesByArtifact().entrySet().stream()
              .filter(value -> value.getKey().coordinate().equals(coordinate))
              .flatMap(value -> value.getValue().stream())
              .collect(java.util.stream.Collectors.toSet());
      final Set<String> removedClasses =
          removedClasses(
              inputClasses,
              entry.getValue().retainedClasses(),
              analysis.trimAnalysis().upperTierClasses().getOrDefault(coordinate, Set.of()));
      if (!removedClasses.isEmpty()) {
        planned.add(new PlannedTrim(coordinate, removedClasses));
      }
    }
    return List.copyOf(planned);
  }

  private static ArtifactSnapshot inputArtifact(
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final ArtifactCoordinate coordinate) {
    return analysis.prepared().resolvedSnapshots().stream()
        .filter(snapshot -> snapshot.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow(
            () -> new IllegalStateException("Trim analysis has no input artifact " + coordinate));
  }

  /* default */ static Set<String> removedClasses(
      final Set<String> inputClasses,
      final Set<String> targetTierRetained,
      final Set<String> upperTierRetained) {
    final Set<String> retained =
        java.util.stream.Stream.concat(targetTierRetained.stream(), upperTierRetained.stream())
            .map(name -> name.replace('/', '.'))
            .collect(java.util.stream.Collectors.toCollection(TreeSet::new));
    final Set<String> removed = new TreeSet<>(inputClasses);
    removed.removeAll(retained);
    return Set.copyOf(removed);
  }

  /** Resolver source used to produce this prediction's dependency graph. */
  /* default */ enum Provenance {
    CAPTURED_EFFECTIVE_RESOLVER,
    DETACHED_CURRENT_MODEL
  }

  /* default */ record PlannedTrim(ArtifactCoordinate coordinate, Set<String> removedClasses)
      implements Comparable<PlannedTrim> {
    PlannedTrim {
      Objects.requireNonNull(coordinate, "coordinate");
      removedClasses = Set.copyOf(new TreeSet<>(removedClasses));
      if (removedClasses.isEmpty()) {
        throw new IllegalArgumentException("A planned trim must remove at least one class");
      }
    }

    @Override
    public int compareTo(final PlannedTrim other) {
      return coordinate.compareTo(other.coordinate);
    }
  }
}
