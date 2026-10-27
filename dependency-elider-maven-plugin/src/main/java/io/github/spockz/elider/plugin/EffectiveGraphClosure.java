// WHY: Computes the whole-identity promotion and reverse ancestor closure required by retained
// nodes.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.EffectiveGraphDecisionIndex.DecisionIndex;
import io.github.spockz.elider.plugin.EffectiveGraphDecisionIndex.Gavce;
import io.github.spockz.elider.plugin.EffectiveGraphGraphIndex.GraphIndex;
import io.github.spockz.elider.plugin.EffectiveGraphGraphIndex.Node;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Applies fixed-point identity promotion to one reachable graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class EffectiveGraphClosure {
  private EffectiveGraphClosure() {
    throw new AssertionError("No instances");
  }

  static Result evaluate(
      final GraphIndex graph,
      final DecisionIndex decisions,
      final Map<Gavce, String> protectedReasons) {
    final Map<Gavce, List<String>> candidates = candidateNodes(graph, decisions, protectedReasons);
    final Set<String> retainedSeeds = retainedSeeds(graph, candidates, protectedReasons);
    final Set<Gavce> promoted = promoteRepeatedOccurrences(graph, candidates, retainedSeeds);
    final Set<Gavce> safeDrops = new LinkedHashSet<>(candidates.keySet());
    safeDrops.removeAll(promoted);
    safeDrops.removeAll(protectedReasons.keySet());
    return new Result(
        promoted,
        safeDrops,
        dispositions(graph, candidates, promoted, protectedReasons),
        directLeafCandidates(graph, candidates, safeDrops, protectedReasons));
  }

  // WHY: Preserve first-seen node order for stable whole-identity decisions.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<Gavce, List<String>> candidateNodes(
      final GraphIndex graph,
      final DecisionIndex decisions,
      final Map<Gavce, String> protectedReasons) {
    final Map<Gavce, List<String>> candidates = new LinkedHashMap<>();
    graph.reachableNodes().values().stream()
        .filter(node -> decisions.isElided(node.identity()))
        .filter(node -> !protectedReasons.containsKey(node.identity()))
        .forEach(
            node ->
                candidates
                    .computeIfAbsent(node.identity(), ignored -> new ArrayList<>())
                    .add(node.nodeId()));
    return candidates;
  }

  private static Set<String> retainedSeeds(
      final GraphIndex graph,
      final Map<Gavce, List<String>> candidates,
      final Map<Gavce, String> protectedReasons) {
    final Set<String> candidateIds = new HashSet<>();
    candidates.values().forEach(candidateIds::addAll);
    final Set<String> retained = new LinkedHashSet<>();
    if (graph.rootNodeId() != null) {
      retained.add(graph.rootNodeId());
    }
    graph.reachableNodes().values().stream()
        .filter(
            node ->
                !candidateIds.contains(node.nodeId())
                    || protectedReasons.containsKey(node.identity()))
        .map(Node::nodeId)
        .forEach(retained::add);
    return retained;
  }

  private static Set<Gavce> promoteRepeatedOccurrences(
      final GraphIndex graph, final Map<Gavce, List<String>> candidates, final Set<String> seeds) {
    final Set<String> retainedNodes = new LinkedHashSet<>(seeds);
    final Set<Gavce> promoted = new LinkedHashSet<>();
    boolean changed;
    do {
      final Set<String> ancestorClosure = graph.ancestorsOf(retainedNodes);
      changed = promoteIdentities(candidates, ancestorClosure, promoted, retainedNodes);
    } while (changed);
    return promoted;
  }

  private static boolean promoteIdentities(
      final Map<Gavce, List<String>> candidates,
      final Set<String> ancestorClosure,
      final Set<Gavce> promoted,
      final Set<String> retainedNodes) {
    boolean changed = false;
    for (final Map.Entry<Gavce, List<String>> candidate : candidates.entrySet()) {
      if (candidate.getValue().stream().anyMatch(ancestorClosure::contains)
          && promoted.add(candidate.getKey())) {
        retainedNodes.addAll(candidate.getValue());
        changed = true;
      }
    }
    return changed;
  }

  // WHY: Stable node order makes the detached diagnostic deterministic.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, EffectiveGraphPolicy.NodeDisposition> dispositions(
      final GraphIndex graph,
      final Map<Gavce, List<String>> candidates,
      final Set<Gavce> promoted,
      final Map<Gavce, String> protectedReasons) {
    final Map<String, EffectiveGraphPolicy.NodeDisposition> result = new LinkedHashMap<>();
    graph
        .reachableNodes()
        .values()
        .forEach(node -> result.put(node.nodeId(), EffectiveGraphPolicy.NodeDisposition.RETAINED));
    candidates.forEach(
        (identity, nodeIds) -> {
          final EffectiveGraphPolicy.NodeDisposition disposition =
              protectedReasons.containsKey(identity)
                  ? EffectiveGraphPolicy.NodeDisposition.PROTECTED
                  : promoted.contains(identity)
                      ? EffectiveGraphPolicy.NodeDisposition.ANCESTOR_PROMOTED
                      : EffectiveGraphPolicy.NodeDisposition.SAFE_ELIDED;
          nodeIds.forEach(nodeId -> result.put(nodeId, disposition));
        });
    return Collections.unmodifiableMap(result);
  }

  private static Set<ArtifactCoordinate> directLeafCandidates(
      final GraphIndex graph,
      final Map<Gavce, List<String>> candidates,
      final Set<Gavce> safeDrops,
      final Map<Gavce, String> protectedReasons) {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>();
    for (final Gavce identity : safeDrops) {
      if (protectedReasons.containsKey(identity)) {
        continue;
      }
      final List<String> nodeIds = candidates.get(identity);
      if (nodeIds == null || nodeIds.size() != 1) {
        continue;
      }
      final String nodeId = nodeIds.getFirst();
      if (graph.parents().getOrDefault(nodeId, List.of()).equals(List.of(graph.rootNodeId()))
          && graph.children().getOrDefault(nodeId, List.of()).isEmpty()) {
        result.add(graph.coordinates().get(identity));
      }
    }
    return EffectiveGraphPolicy.immutableSorted(result);
  }

  /** Detached outcome of repeated-identity ancestor closure. */
  record Result(
      Set<Gavce> ancestorPromoted,
      Set<Gavce> safeDrops,
      Map<String, EffectiveGraphPolicy.NodeDisposition> dispositions,
      Set<ArtifactCoordinate> directLeafCandidates) {
    Result {
      ancestorPromoted = Collections.unmodifiableSet(new LinkedHashSet<>(ancestorPromoted));
      safeDrops = Collections.unmodifiableSet(new LinkedHashSet<>(safeDrops));
      dispositions = Collections.unmodifiableMap(new LinkedHashMap<>(dispositions));
      directLeafCandidates = EffectiveGraphPolicy.immutableSorted(directLeafCandidates);
    }
  }
}
