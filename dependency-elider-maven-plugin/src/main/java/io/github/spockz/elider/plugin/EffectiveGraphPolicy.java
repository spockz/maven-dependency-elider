// WHY: Converts raw whole-artifact decisions into fail-closed graph-safe decisions.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.EffectiveGraphDecisionIndex.DecisionIndex;
import io.github.spockz.elider.plugin.EffectiveGraphDecisionIndex.Gavce;
import io.github.spockz.elider.plugin.EffectiveGraphGraphIndex.GraphIndex;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Pure policy over one planless before/after Maven graph capture. */
// Internal policy; not a plugin API.
final class EffectiveGraphPolicy {
  /** PMD exception for this package-private integration policy API. */
  private static final String DEFAULT_ACCESS_SUPPRESSION = "PMD.CommentDefaultAccessModifier";

  private EffectiveGraphPolicy() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static Evaluation evaluate(
      final List<ResolverArtifactGraphCapturePair> pairs,
      final String expectedProjectKey,
      final ElisionDecision rawDecision) {
    return EffectiveGraphPolicySelection.select(pairs, expectedProjectKey, rawDecision);
  }

  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static Evaluation evaluatePair(
      final ResolverArtifactGraphCapturePair pair, final ElisionDecision rawDecision) {
    validatePair(pair);
    final GraphIndex graph = EffectiveGraphGraphIndex.index(pair.after());
    final DecisionIndex decisions = DecisionIndex.of(rawDecision);
    final Map<Gavce, String> protectedReasons =
        EffectiveGraphProtection.analyze(pair, graph, decisions);

    final EffectiveGraphClosure.Result closure =
        EffectiveGraphClosure.evaluate(graph, decisions, protectedReasons);
    final Set<ArtifactCoordinate> effectiveElided =
        decisions.coordinates(closure.safeDrops(), true);
    final Set<ArtifactCoordinate> effectiveRetained =
        retainedCoordinates(rawDecision, effectiveElided);
    final Set<ArtifactCoordinate> promotedCoordinates =
        decisions.coordinates(closure.ancestorPromoted(), true);
    return new Evaluation(
        pair.projectKey(),
        pair.captureToken(),
        pair.before().graphFingerprint(),
        pair.after().graphFingerprint(),
        effectiveRetained,
        effectiveElided,
        promotedCoordinates,
        coordinateReasons(decisions, protectedReasons),
        closure.dispositions(),
        closure.directLeafCandidates(),
        null);
  }

  private static void validatePair(final ResolverArtifactGraphCapturePair pair) {
    ResolverArtifactGraphSnapshotPayloadValidator.validate(
        pair.before().toPayload(), pair.projectKey());
    ResolverArtifactGraphSnapshotPayloadValidator.validate(
        pair.after().toPayload(), pair.projectKey());
    if (pair.planPresent() || pair.planGeneration() != 0L) {
      throw new IllegalArgumentException("Graph policy requires the initial plan-absent pair");
    }
  }

  // WHY: Preserve the policy evaluation order in the diagnostic map.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<ArtifactCoordinate, String> coordinateReasons(
      final DecisionIndex decisions, final Map<Gavce, String> reasons) {
    final Map<ArtifactCoordinate, String> result = new LinkedHashMap<>();
    reasons.forEach(
        (identity, reason) -> {
          final ArtifactCoordinate coordinate = decisions.coordinate(identity);
          if (coordinate != null) {
            result.put(coordinate, reason);
          }
        });
    return Collections.unmodifiableMap(result);
  }

  private static Set<ArtifactCoordinate> retainedCoordinates(
      final ElisionDecision raw, final Set<ArtifactCoordinate> effectiveElided) {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>(raw.retainedArtifacts());
    raw.elidedArtifacts().stream()
        .filter(coordinate -> !effectiveElided.contains(coordinate))
        .forEach(result::add);
    return immutableSorted(result);
  }

  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static Evaluation failClosed(
      final String projectKey, final ElisionDecision raw, final String reason) {
    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>(raw.retainedArtifacts());
    retained.addAll(raw.elidedArtifacts());
    return new Evaluation(
        projectKey,
        null,
        null,
        null,
        immutableSorted(retained),
        Set.of(),
        Set.of(),
        Map.of(),
        Map.of(),
        Set.of(),
        reason);
  }

  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static Set<ArtifactCoordinate> immutableSorted(final Set<ArtifactCoordinate> values) {
    return Collections.unmodifiableSet(new LinkedHashSet<>(new TreeSet<>(values)));
  }

  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  record Evaluation(
      String projectKey,
      String captureToken,
      String beforeFingerprint,
      String afterFingerprint,
      Set<ArtifactCoordinate> retainedArtifacts,
      Set<ArtifactCoordinate> elidedArtifacts,
      Set<ArtifactCoordinate> ancestorPromotedArtifacts,
      Map<ArtifactCoordinate, String> protectedReasons,
      Map<String, NodeDisposition> nodeDispositions,
      Set<ArtifactCoordinate> directLeafCandidatesForSeparateGate,
      String failClosedReason) {
    Evaluation {
      retainedArtifacts = immutableSorted(retainedArtifacts);
      elidedArtifacts = immutableSorted(elidedArtifacts);
      ancestorPromotedArtifacts = immutableSorted(ancestorPromotedArtifacts);
      protectedReasons = Collections.unmodifiableMap(new LinkedHashMap<>(protectedReasons));
      nodeDispositions = Collections.unmodifiableMap(new LinkedHashMap<>(nodeDispositions));
      directLeafCandidatesForSeparateGate = immutableSorted(directLeafCandidatesForSeparateGate);
    }

    boolean failClosed() {
      return failClosedReason != null;
    }

    ElisionDecision effectiveDecision(final ElisionDecision raw) {
      return new ElisionDecision(
          retainedArtifacts,
          elidedArtifacts,
          raw.retainedClassesPerArtifact(),
          raw.unusedClassesPerArtifact(),
          raw.elapsedNanos());
    }
  }

  /** Effective policy classification for one captured graph node. */
  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  enum NodeDisposition {
    RETAINED,
    SAFE_ELIDED,
    ANCESTOR_PROMOTED,
    PROTECTED
  }
}
