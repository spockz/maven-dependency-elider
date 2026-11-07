// WHY: Computes the effective graph and trim fixed point before staging
// deterministic outputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Computes effective graph reachability before staging outputs. */
final class ElisionReachabilityEngine {
  private ElisionReachabilityEngine() {}

  /* default */ static EffectiveAnalysis finishAnalysis(final PreparedAnalysis prepared)
      throws IOException, MojoFailureException {
    final MavenBanPlan banPlan = prepared.banPlan();
    final ElisionDecision rawDecision = prepared.rawDecision();
    final MavenElisionGraphBinding.Result binding = prepared.graphBinding();
    if (!prepared.inputFingerprint().equals(binding.inventoryFingerprint())) {
      throw new IOException("Graph binding does not match the prepared artifact inventory");
    }
    EffectiveGraphPolicy.Evaluation evaluation = binding.evaluation();
    banPlan.verifyGraph(evaluation);
    MavenArtifactInventory.verifyPreparedInventory(prepared);
    ElisionDecision policyInput = rawDecision;
    ElisionDecision effectiveDecision = evaluation.effectiveDecision(rawDecision);
    final Set<ArtifactCoordinate> forcedUnchanged = initialUnchanged(evaluation);
    final Optional<EffectiveAnalysis> noTrimResult =
        failClosedNoTrimResult(
            prepared,
            banPlan,
            evaluation,
            rawDecision,
            effectiveDecision,
            forcedUnchanged,
            binding);
    if (noTrimResult.isPresent()) {
      return noTrimResult.orElseThrow();
    }
    final Set<String> closureRoots = closureRoots(prepared, binding, effectiveDecision);
    Map<TrimArtifactRootKey, Set<String>> discoveredRoots = Map.of();
    TrimAnalysisResult analysis;
    while (true) {
      final TrimRequest trimRequest =
          TrimRequestFactory.fromPreparedAnalysis(
              prepared, effectiveDecision.retainedArtifacts(), closureRoots);
      analysis =
          MavenDependencyTrimmer.analyzeInMemory(trimRequest, discoveredRoots, forcedUnchanged);
      banPlan.verifyRetainedClosure(prepared, effectiveDecision, analysis, forcedUnchanged);
      final Set<ArtifactCoordinate> newlyReachedDrops =
          newlyReachedDrops(analysis, effectiveDecision);
      banPlan.verifyNoPromotion(newlyReachedDrops);
      if (newlyReachedDrops.isEmpty()) {
        banPlan.verifyGraph(evaluation);
        return new EffectiveAnalysis(
            prepared,
            banPlan,
            evaluation,
            rawDecision,
            effectiveDecision,
            forcedUnchanged,
            analysis,
            binding.inventoryFingerprint(),
            binding.operationFingerprint(),
            projection(binding, evaluation));
      }
      if (binding.pair() == null) {
        throw new IOException("Reachability found a raw drop without a bound graph pair");
      }
      policyInput = promoteForBytecode(policyInput, newlyReachedDrops);
      evaluation = EffectiveGraphPolicy.evaluatePair(binding.pair(), policyInput);
      banPlan.verifyGraph(evaluation);
      effectiveDecision = evaluation.effectiveDecision(rawDecision);
      forcedUnchanged.addAll(newlyReachedDrops);
      addUnchangedPolicyArtifacts(evaluation, forcedUnchanged);
      discoveredRoots =
          DiscoveredTrimRoots.from(prepared.resolvedSnapshots(), analysis.candidateRoots());
    }
  }

  private static Optional<EffectiveAnalysis> failClosedNoTrimResult(
      final PreparedAnalysis prepared,
      final MavenBanPlan banPlan,
      final EffectiveGraphPolicy.Evaluation evaluation,
      final ElisionDecision rawDecision,
      final ElisionDecision effectiveDecision,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final MavenElisionGraphBinding.Result binding)
      throws IOException {
    if (prepared.options().trim().enabled() || !evaluation.failClosed() || banPlan.requested()) {
      return Optional.empty();
    }
    final TrimRequest request =
        TrimRequestFactory.fromPreparedAnalysis(
            prepared, effectiveDecision.retainedArtifacts(), prepared.sourceRequiredClasses());
    final TrimExecutionEnvironment environment =
        MavenDependencyTrimmer.executionEnvironment(request);
    final TrimAnalysisResult analysis =
        new TrimAnalysisResult(
            Map.of(),
            Map.of(),
            Set.of(),
            0,
            environment.targetRelease(),
            environment.runtimeRelease(),
            List.of(),
            List.of(),
            Map.of());
    return Optional.of(
        new EffectiveAnalysis(
            prepared,
            banPlan,
            evaluation,
            rawDecision,
            effectiveDecision,
            forcedUnchanged,
            analysis,
            binding.inventoryFingerprint(),
            binding.operationFingerprint(),
            projection(binding, evaluation)));
  }

  /* package */ static Analysis finishEffectiveOutputs(final EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return MavenEffectiveAnalysisReport.create(
        effective, MavenDependencyTrimmer.stageEffectiveOutputs(effective));
  }

  private static Set<ArtifactCoordinate> initialUnchanged(
      final EffectiveGraphPolicy.Evaluation evaluation) {
    final Set<ArtifactCoordinate> unchanged = new LinkedHashSet<>();
    addUnchangedPolicyArtifacts(evaluation, unchanged);
    return unchanged;
  }

  private static Set<String> closureRoots(
      final PreparedAnalysis prepared,
      final MavenElisionGraphBinding.Result binding,
      final ElisionDecision decision) {
    final Set<String> roots = new LinkedHashSet<>(prepared.sourceRequiredClasses());
    if (!prepared.options().trim().enabled()
        && binding.pair() != null
        && !decision.elidedArtifacts().isEmpty()) {
      prepared
          .index()
          .classesByArtifact()
          .forEach(
              (artifact, classes) -> {
                final ArtifactCoordinate coordinate = artifact.coordinate();
                if (decision.retainedArtifacts().contains(coordinate)
                    && MavenDependencyTrimmer.JAR_TYPE.equals(coordinate.type())
                    && MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
                        coordinate.scope())) {
                  roots.addAll(classes);
                }
              });
    }
    return Set.copyOf(roots);
  }

  private static ResolverArtifactGraphProjection projection(
      final MavenElisionGraphBinding.Result binding,
      final EffectiveGraphPolicy.Evaluation evaluation)
      throws IOException {
    if (binding.pair() == null || evaluation.failClosed()) {
      return null;
    }
    return ResolverArtifactGraphProjection.create(binding.pair(), evaluation.nodeDispositions());
  }

  private static void addUnchangedPolicyArtifacts(
      final EffectiveGraphPolicy.Evaluation evaluation, final Set<ArtifactCoordinate> unchanged) {
    unchanged.addAll(evaluation.ancestorPromotedArtifacts());
    unchanged.addAll(evaluation.protectedReasons().keySet());
  }

  private static ElisionDecision promoteForBytecode(
      final ElisionDecision decision, final Set<ArtifactCoordinate> promoted) {
    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>(decision.retainedArtifacts());
    final Set<ArtifactCoordinate> elided = new LinkedHashSet<>(decision.elidedArtifacts());
    promoted.stream().filter(elided::remove).forEach(retained::add);
    return new ElisionDecision(
        retained,
        elided,
        decision.retainedClassesPerArtifact(),
        decision.unusedClassesPerArtifact(),
        decision.elapsedNanos());
  }

  private static Set<ArtifactCoordinate> newlyReachedDrops(
      final TrimAnalysisResult analysis, final ElisionDecision effectiveDecision) {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>(analysis.reachableArtifacts());
    result.retainAll(effectiveDecision.elidedArtifacts());
    return result;
  }
}
