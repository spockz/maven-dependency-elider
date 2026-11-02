// WHY: Computes the effective graph and trim fixed point before staging
// deterministic outputs.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ArtifactSnapshot;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;

/** Computes effective graph reachability before staging outputs. */
final class ElisionReachabilityEngine {
  private ElisionReachabilityEngine() {}

  /* default */ static boolean requiresTierAwareMrjarTrim(final PreparedAnalysis prepared)
      throws IOException {
    final AnalysisOptions options = prepared.options();
    if (!options.trim().enabled()) {
      return false;
    }
    final Set<ArtifactCoordinate> retained = prepared.rawDecision().retainedArtifacts();
    boolean hasMultiRelease = false;
    boolean hasOtherCandidate = false;
    for (final ArtifactSnapshot snapshot : prepared.resolvedSnapshots()) {
      if (!retained.contains(snapshot.coordinate())
          || !"jar".equals(snapshot.coordinate().type())
          || !Set.of("compile", "runtime").contains(snapshot.coordinate().scope())) {
        continue;
      }
      if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())) {
        hasMultiRelease = true;
        if (MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING.equals(options.trim().mrjarStrategy())) {
          return true;
        }
      } else {
        hasOtherCandidate = true;
      }
    }
    return hasMultiRelease && hasOtherCandidate;
  }

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
    banPlan.verifyAuditBytesFresh();
    ElisionDecision policyInput = rawDecision;
    ElisionDecision effectiveDecision = evaluation.effectiveDecision(rawDecision);
    final Set<ArtifactCoordinate> forcedUnchanged =
        initialUnchanged(prepared, evaluation, effectiveDecision);
    Map<TrimArtifactRootKey, Set<String>> discoveredRoots = Map.of();
    TrimAnalysisResult analysis;
    while (true) {
      MavenArtifactInventory.verifyPreparedInventory(prepared);
      banPlan.verifyAuditBytesFresh();
      final TrimRequest trimRequest =
          TrimRequestFactory.fromPreparedAnalysis(
              prepared, effectiveDecision.retainedArtifacts(), prepared.sourceRequiredClasses());
      analysis =
          MavenDependencyTrimmer.analyzeInMemory(trimRequest, discoveredRoots, forcedUnchanged);
      MavenArtifactInventory.verifyPreparedInventory(prepared);
      banPlan.verifyAuditBytesFresh();
      banPlan.verifyRetainedClosure(prepared, effectiveDecision, analysis, forcedUnchanged);
      final Set<ArtifactCoordinate> newlyReachedDrops =
          newlyReachedDrops(analysis, effectiveDecision);
      banPlan.verifyNoPromotion(newlyReachedDrops);
      if (newlyReachedDrops.isEmpty()) {
        banPlan.verifyGraph(evaluation);
        banPlan.verifyAuditBytesFresh();
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
      banPlan.verifyAuditBytesFresh();
      effectiveDecision = evaluation.effectiveDecision(rawDecision);
      forcedUnchanged.addAll(newlyReachedDrops);
      addUnchangedPolicyArtifacts(evaluation, forcedUnchanged);
      discoveredRoots =
          DiscoveredTrimRoots.from(prepared.resolvedSnapshots(), analysis.candidateRoots());
    }
  }

  /* package */ static Analysis finishEffectiveOutputs(final EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return MavenEffectiveAnalysisReport.create(
        effective, MavenDependencyTrimmer.stageEffectiveOutputs(effective));
  }

  private static Set<ArtifactCoordinate> initialUnchanged(
      final PreparedAnalysis prepared,
      final EffectiveGraphPolicy.Evaluation evaluation,
      final ElisionDecision decision) {
    final Set<ArtifactCoordinate> unchanged = new LinkedHashSet<>();
    addUnchangedPolicyArtifacts(evaluation, unchanged);
    if (!prepared.options().trim().enabled()) {
      unchanged.addAll(decision.retainedArtifacts());
    }
    return unchanged;
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
