// WHY: Selects the unique planless graph pair whose inventory matches one raw analyzer decision.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.plugin.EffectiveGraphDecisionIndex.DecisionKey;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Binds a raw decision to one captured inventory before policy evaluation. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphPolicySelection {
  private EffectiveGraphPolicySelection() {
    throw new AssertionError("No instances");
  }

  static EffectiveGraphPolicy.Evaluation select(
      final List<ResolverArtifactGraphCapturePair> pairs,
      final String expectedProjectKey,
      final ElisionDecision rawDecision) {
    Objects.requireNonNull(pairs, "pairs");
    Objects.requireNonNull(expectedProjectKey, "expectedProjectKey");
    Objects.requireNonNull(rawDecision, "rawDecision");
    final List<ResolverArtifactGraphCapturePair> compatible =
        pairs.stream()
            .filter(pair -> pair.projectKey().equals(expectedProjectKey))
            .filter(pair -> !pair.planPresent() && pair.planGeneration() == 0L)
            .filter(pair -> decisionInventoryMatches(pair.after(), rawDecision))
            .toList();
    if (compatible.size() != 1 || !uniqueTokens(pairs)) {
      return EffectiveGraphPolicy.failClosed(
          expectedProjectKey,
          rawDecision,
          compatible.isEmpty()
              ? "No unique plan-absent graph pair matches the raw decision inventory"
              : "Multiple plan-absent graph pairs match the raw decision inventory");
    }
    return EffectiveGraphPolicy.evaluatePair(compatible.getFirst(), rawDecision);
  }

  private static boolean uniqueTokens(final List<ResolverArtifactGraphCapturePair> pairs) {
    final Set<String> tokens = new HashSet<>();
    return pairs.stream().allMatch(pair -> tokens.add(pair.captureToken()));
  }

  private static boolean decisionInventoryMatches(
      final ResolverArtifactGraphSnapshot snapshot, final ElisionDecision decision) {
    final Set<DecisionKey> expected = new LinkedHashSet<>();
    decision.retainedArtifacts().forEach(coordinate -> expected.add(DecisionKey.of(coordinate)));
    decision.elidedArtifacts().forEach(coordinate -> expected.add(DecisionKey.of(coordinate)));
    final Set<DecisionKey> actual = new LinkedHashSet<>();
    for (final Map<String, Object> node : snapshot.nodes()) {
      if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
        continue;
      }
      if (Objects.equals(
          node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), snapshot.rootNodeId())) {
        continue;
      }
      final Object artifactValue = node.get(ResolverArtifactGraphSnapshotSchema.ARTIFACT);
      final Object scopeValue = node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE);
      if (!(artifactValue instanceof Map<?, ?> artifact) || !(scopeValue instanceof String scope)) {
        return false;
      }
      actual.add(DecisionKey.of(artifact, scope));
    }
    return actual.equals(expected);
  }
}
