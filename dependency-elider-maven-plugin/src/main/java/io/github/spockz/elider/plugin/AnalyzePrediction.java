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
import java.util.TreeMap;
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
  /** Report marker for root module descriptor removal. */
  private static final String CLASSPATH_ONLY_STATUS = "classpath-only";

  /** Report marker for an ordinary single-release output. */
  private static final String NOT_MULTI_RELEASE_STATUS = "not_multi_release";

  /** Report marker for an output elevated from a multi-release archive. */
  private static final String ELEVATED_STATUS = "elevated_and_trimmed";

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
    final List<PlannedTrim> trims = plannedTrims(analysis, trimRequest);
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
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final TrimRequest trimRequest)
      throws IOException {
    final List<TrimCandidate> candidates = plannedOutputCandidates(analysis, trimRequest);
    final Map<ArtifactCoordinate, List<ServiceDescriptorChange>> descriptorChanges =
        plannedServiceDescriptorChanges(candidates);
    final Map<ArtifactCoordinate, Set<String>> removedByCoordinate =
        removedClassesByCoordinate(analysis);
    final Set<ArtifactCoordinate> outputCoordinates =
        outputCoordinates(analysis, candidates, removedByCoordinate, descriptorChanges);
    final List<PlannedTrim> planned = new java.util.ArrayList<>();
    for (final ArtifactCoordinate coordinate : outputCoordinates) {
      planned.add(
          new PlannedTrim(
              coordinate,
              removedByCoordinate.getOrDefault(coordinate, Set.of()),
              descriptorChanges.getOrDefault(coordinate, List.of()),
              mrjarStatus(analysis, coordinate)));
    }
    return List.copyOf(planned);
  }

  /* WHY: Separates class removal facts from output eligibility policy. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<ArtifactCoordinate, Set<String>> removedClassesByCoordinate(
      final ElisionAnalysisModel.EffectiveAnalysis analysis) throws IOException {
    final Map<ArtifactCoordinate, Set<String>> removedByCoordinate = new TreeMap<>();
    for (final Map.Entry<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> entry :
        analysis.trimAnalysis().candidateAnalyses().entrySet()) {
      final ArtifactCoordinate coordinate = entry.getKey();
      if (mustSkipRemovedClasses(analysis, coordinate)) {
        continue;
      }
      final ArtifactSnapshot artifact = inputArtifact(analysis, coordinate);
      if (isUnsupportedPassThrough(analysis, artifact)) {
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
        removedByCoordinate.put(coordinate, removedClasses);
      }
    }
    return Map.copyOf(removedByCoordinate);
  }

  private static boolean mustSkipRemovedClasses(
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final ArtifactCoordinate coordinate) {
    return !analysis.effectiveDecision().retainedArtifacts().contains(coordinate)
        || analysis.forcedUnchangedCoordinates().contains(coordinate);
  }

  private static boolean isUnsupportedPassThrough(
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final ArtifactSnapshot artifact)
      throws IOException {
    return analysis.prepared().options().trim().enabled()
        && MavenDependencyTrimmer.MRJAR_PASS_THROUGH.equals(
            analysis.prepared().options().trim().mrjarStrategy())
        && MultiReleaseClassInventory.hasUnsupportedVersionedClasses(artifact.filePath());
  }

  private static Set<ArtifactCoordinate> outputCoordinates(
      final ElisionAnalysisModel.EffectiveAnalysis analysis,
      final List<TrimCandidate> candidates,
      final Map<ArtifactCoordinate, Set<String>> removedByCoordinate,
      final Map<ArtifactCoordinate, List<ServiceDescriptorChange>> descriptorChanges)
      throws IOException {
    final Set<ArtifactCoordinate> outputCoordinates = new TreeSet<>(removedByCoordinate.keySet());
    outputCoordinates.addAll(descriptorChanges.keySet());
    addVerticalOutputCoordinates(analysis, candidates, outputCoordinates);
    addClasspathOnlyOutputCoordinates(analysis, candidates, outputCoordinates);
    return outputCoordinates;
  }

  private static void addVerticalOutputCoordinates(
      final ElisionAnalysisModel.EffectiveAnalysis analysis,
      final List<TrimCandidate> candidates,
      final Set<ArtifactCoordinate> outputCoordinates) {
    if (!analysis.prepared().options().trim().enabled()
        || !MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(
            analysis.prepared().options().trim().mrjarStrategy())) {
      return;
    }
    candidates.stream()
        .filter(candidate -> candidate.archive().multiRelease())
        .map(candidate -> candidate.archive().snapshot().coordinate())
        .forEach(outputCoordinates::add);
  }

  private static void addClasspathOnlyOutputCoordinates(
      final ElisionAnalysisModel.EffectiveAnalysis analysis,
      final List<TrimCandidate> candidates,
      final Set<ArtifactCoordinate> outputCoordinates)
      throws IOException {
    if (!analysis.prepared().options().trim().enabled()
        || !MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(
            analysis.prepared().options().trim().mrjarStrategy())) {
      return;
    }
    for (final TrimCandidate candidate : candidates) {
      final ArtifactCoordinate coordinate = candidate.archive().snapshot().coordinate();
      if (CLASSPATH_ONLY_STATUS.equals(mrjarStatus(analysis, coordinate))) {
        outputCoordinates.add(coordinate);
      }
    }
  }

  private static String mrjarStatus(
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final ArtifactCoordinate coordinate)
      throws IOException {
    if (analysis.trimAnalysis().upperTierClasses().containsKey(coordinate)) {
      return ELEVATED_STATUS;
    }
    if (analysis.prepared().options().trim().enabled()
        && MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY.equals(
            analysis.prepared().options().trim().mrjarStrategy())
        && MultiReleaseLibraryProjection.hasRootModuleDescriptor(
            inputArtifact(analysis, coordinate).filePath())) {
      return CLASSPATH_ONLY_STATUS;
    }
    return NOT_MULTI_RELEASE_STATUS;
  }

  private static List<TrimCandidate> plannedOutputCandidates(
      final ElisionAnalysisModel.EffectiveAnalysis analysis, final TrimRequest trimRequest)
      throws IOException {
    if (!analysis.prepared().options().trim().enabled()) {
      return List.of();
    }
    final TrimGenerationPublisher.EffectiveOutputPlan outputPlan =
        EffectiveOutputPlanFactory.create(analysis);
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(trimRequest);
    final TrimCandidatePlanner.CandidatePlan candidates =
        EffectiveCandidatePlanner.effectiveCandidatePlan(
            trimRequest.project(),
            passThrough.retainedLibraries(),
            passThrough.retained(),
            trimRequest.scanInputs().classIndex().classesByArtifact(),
            outputPlan);
    TrimCandidatePlanner.assignEffectiveAnalyses(candidates, analysis.trimAnalysis());
    ServiceProviderTrimInventory.planDescriptorOutputs(outputPlan, candidates.work());
    return candidates.work();
  }

  private static Map<ArtifactCoordinate, List<ServiceDescriptorChange>>
      plannedServiceDescriptorChanges(final List<TrimCandidate> candidates) {
    return candidates.stream()
        .filter(candidate -> !candidate.descriptorPlan().changes().isEmpty())
        .collect(
            java.util.stream.Collectors.toUnmodifiableMap(
                candidate -> candidate.archive().snapshot().coordinate(),
                candidate -> candidate.descriptorPlan().changes()));
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

  /* default */ record PlannedTrim(
      ArtifactCoordinate coordinate,
      Set<String> removedClasses,
      List<ServiceDescriptorChange> serviceDescriptorChanges,
      String mrjarStatus)
      implements Comparable<PlannedTrim> {
    /* default */ PlannedTrim(
        final ArtifactCoordinate coordinate, final Set<String> removedClasses) {
      this(coordinate, removedClasses, List.of(), null);
    }

    /* default */ PlannedTrim(
        final ArtifactCoordinate coordinate,
        final Set<String> removedClasses,
        final List<ServiceDescriptorChange> serviceDescriptorChanges) {
      this(coordinate, removedClasses, serviceDescriptorChanges, null);
    }

    PlannedTrim {
      Objects.requireNonNull(coordinate, "coordinate");
      removedClasses = Set.copyOf(new TreeSet<>(removedClasses));
      serviceDescriptorChanges = serviceDescriptorChanges.stream().sorted().toList();
      if (removedClasses.isEmpty()
          && serviceDescriptorChanges.isEmpty()
          && !"elevated_and_trimmed".equals(mrjarStatus)
          && !"classpath-only".equals(mrjarStatus)) {
        throw new IllegalArgumentException(
            "A planned output must remove classes, change a service descriptor, or transform a"
                + " modular archive");
      }
    }

    @Override
    public int compareTo(final PlannedTrim other) {
      return coordinate.compareTo(other.coordinate);
    }
  }
}
