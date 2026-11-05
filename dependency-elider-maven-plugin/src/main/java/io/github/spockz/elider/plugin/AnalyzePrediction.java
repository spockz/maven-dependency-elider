// WHY: Separates Analyze's in-memory prediction from trim output records and publication state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisEvidence;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.MavenAnalysisResolutionContext.Provenance;
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
    MavenBanPlan banPlan,
    List<MavenElisionReportSnapshot.ToleratedDuplicateClass> toleratedDuplicates,
    MavenElisionPolicyIdentity policy,
    TrimExecutionEnvironment executionEnvironment,
    List<String> rawDroppedCoordinates,
    MediatedGraphReport mediatedGraph) {
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
        MavenBanPlan.empty(),
        List.of());
  }

  @SuppressWarnings("PMD.ExcessiveParameterList")
  /* default */ AnalyzePrediction(
      final Provenance provenance,
      final List<ArtifactSnapshot> inputArtifacts,
      final List<ArtifactCoordinate> retainedArtifacts,
      final List<ArtifactCoordinate> wouldElideArtifacts,
      final List<PlannedTrim> plannedTrims,
      final AnalysisEvidence evidence,
      final String environmentFingerprint,
      final String inventoryFingerprint,
      final String operationFingerprint,
      final MavenBanPlan banPlan,
      final List<MavenElisionReportSnapshot.ToleratedDuplicateClass> toleratedDuplicates) {
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
        banPlan,
        toleratedDuplicates,
        new MavenElisionPolicyIdentity(List.of(), List.of(), operationFingerprint),
        new TrimExecutionEnvironment(Runtime.version().feature(), Runtime.version().feature()),
        List.of(),
        MediatedGraphReport.unavailable("No graph captured"));
  }

  AnalyzePrediction {
    Objects.requireNonNull(provenance, "provenance");
    inputArtifacts = List.copyOf(inputArtifacts);
    retainedArtifacts = retainedArtifacts.stream().sorted().toList();
    wouldElideArtifacts = wouldElideArtifacts.stream().sorted().toList();
    plannedTrims = plannedTrims.stream().sorted().toList();
    if (plannedTrims.stream().map(value -> value.coordinate().toId()).distinct().count()
        != plannedTrims.size()) {
      throw new IllegalArgumentException("Cannot capture multiple plans for one component");
    }
    toleratedDuplicates = List.copyOf(toleratedDuplicates);
    Objects.requireNonNull(evidence, "evidence");
    Objects.requireNonNull(environmentFingerprint, "environmentFingerprint");
    Objects.requireNonNull(inventoryFingerprint, "inventoryFingerprint");
    Objects.requireNonNull(operationFingerprint, "operationFingerprint");
    Objects.requireNonNull(banPlan, "banPlan");
    Objects.requireNonNull(policy, "policy");
    Objects.requireNonNull(executionEnvironment, "executionEnvironment");
    rawDroppedCoordinates = List.copyOf(rawDroppedCoordinates);
    Objects.requireNonNull(mediatedGraph, "mediatedGraph");
  }

  /* default */ static AnalyzePrediction from(final ElisionAnalysisModel.EffectiveAnalysis analysis)
      throws IOException {
    final TrimRequest trimRequest =
        TrimRequestFactory.fromPreparedAnalysis(
            analysis.prepared(),
            analysis.effectiveDecision().retainedArtifacts(),
            analysis.prepared().pruningRequiredClasses());
    final List<PlannedTrim> trims = plannedTrims(analysis);
    return new AnalyzePrediction(
        analysis.prepared().resolutionContext().provenance(),
        analysis.prepared().resolvedSnapshots(),
        List.copyOf(analysis.effectiveDecision().retainedArtifacts()),
        List.copyOf(analysis.effectiveDecision().elidedArtifacts()),
        trims,
        ElisionAnalysisModel.evidence(analysis.prepared()),
        analysis.prepared().resolutionContext().environment().fingerprint(),
        analysis.inventoryFingerprint(),
        analysis.operationFingerprint(),
        analysis.banPlan(),
        DuplicateClasses.resolveRetained(trimRequest).stream()
            .map(MavenElisionReportSnapshot.ToleratedDuplicateClass::from)
            .toList(),
        analysis
            .prepared()
            .policyOptions()
            .withOperationFingerprint(analysis.operationFingerprint()),
        new TrimExecutionEnvironment(
            analysis.trimAnalysis().targetRelease(), analysis.trimAnalysis().runtimeRelease()),
        analysis.prepared().traceDecision().elidedArtifacts().stream()
            .filter(c -> !analysis.banPlan().forcedAbsentAfterResolution().contains(c))
            .map(Object::toString)
            .sorted()
            .toList(),
        MediatedGraphReport.createPrediction(
            analysis.prepared().graphBinding().pair(),
            analysis.graphEvaluation(),
            analysis.effectiveDecision().elidedArtifacts(),
            trims.stream()
                .map(PlannedTrim::coordinate)
                .collect(java.util.stream.Collectors.toSet()),
            analysis.prepared().project().getGroupId()
                + ":"
                + analysis.prepared().project().getArtifactId()
                + ":"
                + analysis.prepared().project().getVersion()));
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
