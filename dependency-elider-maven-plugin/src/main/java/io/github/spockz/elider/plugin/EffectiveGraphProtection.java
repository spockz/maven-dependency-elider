// WHY: Applies path and conflict safeguards before graph closure can classify candidate removals.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Collects the path and conflict cases that must override a raw artifact drop. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphProtection {
  /** Path scopes for which raw policy metadata is sufficient. */
  private static final Set<String> ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** PMD exception for local ordered maps that stabilize diagnostic output. */
  private static final String ORDERED_MAP_SUPPRESSION = "PMD.UseConcurrentHashMap";

  private EffectiveGraphProtection() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings(ORDERED_MAP_SUPPRESSION)
  static Map<EffectiveGraphDecisionIndex.Gavce, String> analyze(
      final ResolverArtifactGraphCapturePair pair,
      final EffectiveGraphGraphIndex.GraphIndex graph,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions) {
    final Map<EffectiveGraphDecisionIndex.Gavce, String> reasons = new LinkedHashMap<>();
    decisions.ambiguous().forEach(key -> reasons.put(key, "raw outcome or scope is ambiguous"));
    protectConflictedFamilies(pair, decisions, reasons);
    protectPathMetadata(graph, decisions, reasons);
    protectNullChildren(graph, decisions, reasons);
    return reasons;
  }

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.AvoidInstantiatingObjectsInLoops"})
  private static void protectConflictedFamilies(
      final ResolverArtifactGraphCapturePair pair,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> protectedReasons) {
    final Map<EffectiveGraphDecisionIndex.Family, Set<String>> preVersions = new HashMap<>();
    for (final Map<String, Object> node : pair.before().nodes()) {
      final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
      if (identity != null) {
        preVersions
            .computeIfAbsent(identity.family(), ignored -> new HashSet<>())
            .add(identity.version());
      }
    }
    decisions
        .outcomes()
        .forEach(
            (identity, outcome) -> {
              if (outcome == EffectiveGraphDecisionIndex.DecisionOutcome.ELIDED
                  && preVersions.getOrDefault(identity.family(), Set.of()).size() > 1) {
                protectedReasons.put(identity, "pre-mediation graph contains a competing version");
              }
            });
    protectWinnerReferences(pair.after(), decisions, protectedReasons);
    protectWinnerReferences(pair.before(), decisions, protectedReasons);
  }

  private static void protectWinnerReferences(
      final ResolverArtifactGraphSnapshot snapshot,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> protectedReasons) {
    for (final Map<String, Object> node : snapshot.nodes()) {
      if (!Boolean.TRUE.equals(
          node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_PRESENT))) {
        continue;
      }
      final EffectiveGraphDecisionIndex.Gavce source = EffectiveGraphDecisionIndex.gavce(node);
      if (source != null && decisions.isElided(source)) {
        protectedReasons.put(source, "conflict winner metadata is present");
      }
      protectWinnerNodeReference(node, snapshot, decisions, protectedReasons);
      protectExternalWinner(node, decisions, protectedReasons);
      if (source != null && decisions.isElided(source)) {
        protectedReasons.put(source, "conflict winner value has no mapped identity");
      }
    }
  }

  private static void protectWinnerNodeReference(
      final Map<String, Object> node,
      final ResolverArtifactGraphSnapshot snapshot,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> protectedReasons) {
    final Object winnerValue =
        node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_NODE_ID);
    if (!(winnerValue instanceof String winnerNodeId)) {
      return;
    }
    snapshot.nodes().stream()
        .filter(
            candidate ->
                winnerNodeId.equals(candidate.get(ResolverArtifactGraphSnapshotSchema.NODE_ID)))
        .map(EffectiveGraphDecisionIndex::gavce)
        .filter(decisions::isElided)
        .forEach(identity -> protectedReasons.put(identity, "referenced as a conflict winner"));
  }

  private static void protectExternalWinner(
      final Map<String, Object> node,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> protectedReasons) {
    final EffectiveGraphDecisionIndex.Gavce external =
        EffectiveGraphDecisionIndex.gavce(
            node.get(ResolverArtifactGraphSnapshotSchema.CONFLICT_WINNER_EXTERNAL_ARTIFACT));
    if (external != null && decisions.isElided(external)) {
      protectedReasons.put(external, "referenced as an external conflict winner");
    }
  }

  @SuppressWarnings(ORDERED_MAP_SUPPRESSION)
  private static void protectPathMetadata(
      final EffectiveGraphGraphIndex.GraphIndex graph,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> protectedReasons) {
    final Map<EffectiveGraphDecisionIndex.Gavce, String> metadataByIdentity = new HashMap<>();
    for (final EffectiveGraphGraphIndex.Node node : graph.reachableNodes().values()) {
      if (!decisions.isElided(node.identity())) {
        continue;
      }
      final String metadata =
          ResolverArtifactGraphSnapshot.canonicalJson(pathMetadata(node.payload()));
      final String previous = metadataByIdentity.putIfAbsent(node.identity(), metadata);
      if (previous != null && !previous.equals(metadata)) {
        protectedReasons.put(node.identity(), "repeated artifact paths have different metadata");
      }
      if (!pathScopeMatches(node.payload(), decisions.coordinate(node.identity()))) {
        protectedReasons.put(node.identity(), "artifact scope does not match the path scope");
      }
    }
  }

  @SuppressWarnings(ORDERED_MAP_SUPPRESSION)
  private static Map<String, Object> pathMetadata(final Map<String, Object> node) {
    final Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put("effectiveScope", node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE));
    metadata.put("dependency", node.get(ResolverArtifactGraphSnapshotSchema.DEPENDENCY));
    metadata.put(
        "originalScopePresent",
        node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE_PRESENT));
    metadata.put("originalScope", node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_SCOPE));
    metadata.put(
        "originalOptionalityPresent",
        node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_OPTIONALITY_PRESENT));
    metadata.put(
        "originalOptionality", node.get(ResolverArtifactGraphSnapshotSchema.ORIGINAL_OPTIONALITY));
    return metadata;
  }

  private static boolean pathScopeMatches(
      final Map<String, Object> node, final ArtifactCoordinate coordinate) {
    if (coordinate == null || !ELIGIBLE_SCOPES.contains(coordinate.scope())) {
      return false;
    }
    final Object dependencyValue = node.get(ResolverArtifactGraphSnapshotSchema.DEPENDENCY);
    if (!(dependencyValue instanceof Map<?, ?> dependency)) {
      return false;
    }
    return coordinate.scope().equals(node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE))
        && coordinate.scope().equals(dependency.get(ResolverArtifactGraphSnapshotSchema.SCOPE))
        && (dependency.get(ResolverArtifactGraphSnapshotSchema.OPTIONAL) == null
            || dependency.get(ResolverArtifactGraphSnapshotSchema.OPTIONAL) instanceof Boolean)
        && dependency.get(ResolverArtifactGraphSnapshotSchema.EXCLUSIONS)
            instanceof java.util.List<?>;
  }

  private static void protectNullChildren(
      final EffectiveGraphGraphIndex.GraphIndex graph,
      final EffectiveGraphDecisionIndex.DecisionIndex decisions,
      final Map<EffectiveGraphDecisionIndex.Gavce, String> reasons) {
    for (final Map<String, Object> edge : graph.nullChildEdges()) {
      final EffectiveGraphGraphIndex.Node parent =
          graph.reachableNodes().get(edge.get(ResolverArtifactGraphSnapshotSchema.PARENT_NODE_ID));
      if (parent != null && decisions.isElided(parent.identity())) {
        reasons.put(parent.identity(), "graph contains an unknown null child edge");
      }
    }
  }
}
