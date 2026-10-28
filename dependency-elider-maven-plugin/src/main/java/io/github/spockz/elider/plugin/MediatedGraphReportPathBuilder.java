/* WHY: Derives stable occurrence paths from an immutable mediated graph snapshot. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Builds shortest root paths for persisted graph occurrences. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal report construction API.
final class MediatedGraphReportPathBuilder {
  /** Persisted output classification for whole-artifact removals. */
  private static final String DROPPED_KIND = "WHOLE_ARTIFACT_DROPPED";

  /** Persisted output classification for class-level trimming. */
  private static final String TRIMMED_KIND = "CLASS_TRIMMED";

  /** Policy disposition required to report a whole-artifact removal. */
  private static final String SAFE_ELIDED = "SAFE_ELIDED";

  private MediatedGraphReportPathBuilder() {
    throw new AssertionError("No instances");
  }

  static List<MediatedGraphReport.ArtifactPath> build(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> statuses,
      final Set<ArtifactCoordinate> effectiveDrops,
      final List<ArtifactTrimRecord> trimRecords,
      final String projectGav)
      throws IOException {
    final Map<String, List<String>> pathsByNode = MediatedGraphShortestPaths.from(snapshot);
    final Map<String, MediatedGraphReport.NodeStatus> statusesByNode = statusesByNode(statuses);
    final Set<EffectiveGraphDecisionIndex.DecisionKey> dropKeys = decisionKeys(effectiveDrops);
    final Set<EffectiveGraphDecisionIndex.DecisionKey> trimKeys = trimKeys(trimRecords);
    final List<MediatedGraphReport.ArtifactPath> result = new ArrayList<>();
    for (final Map<String, Object> node : snapshot.nodes()) {
      appendPath(
          node, snapshot, pathsByNode, statusesByNode, dropKeys, trimKeys, projectGav, result);
    }
    result.sort(
        Comparator.comparing(MediatedGraphReport.ArtifactPath::coordinate)
            .thenComparing(MediatedGraphReport.ArtifactPath::nodeId)
            .thenComparing(MediatedGraphReport.ArtifactPath::kind));
    return List.copyOf(result);
  }

  @SuppressWarnings(
      "PMD.UseConcurrentHashMap") // Single-threaded report assembly uses a lookup map.
  private static Map<String, MediatedGraphReport.NodeStatus> statusesByNode(
      final List<MediatedGraphReport.NodeStatus> statuses) {
    final Map<String, MediatedGraphReport.NodeStatus> result = new HashMap<>();
    statuses.forEach(status -> result.put(status.nodeId(), status));
    return result;
  }

  private static void appendPath(
      final Map<String, Object> node,
      final ResolverArtifactGraphSnapshot snapshot,
      final Map<String, List<String>> pathsByNode,
      final Map<String, MediatedGraphReport.NodeStatus> statusesByNode,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> dropKeys,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> trimKeys,
      final String projectGav,
      final List<MediatedGraphReport.ArtifactPath> result)
      throws IOException {
    if (!Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE))) {
      return;
    }
    final String nodeId = (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
    final ArtifactCoordinate coordinate = MediatedGraphReportPathCoordinate.coordinate(node);
    if (coordinate == null) {
      return;
    }
    final MediatedGraphReport.NodeStatus status = statusesByNode.get(nodeId);
    final EffectiveGraphDecisionIndex.DecisionKey key =
        EffectiveGraphDecisionIndex.DecisionKey.of(coordinate);
    final String kind = pathKind(key, status, dropKeys, trimKeys);
    if (kind == null) {
      return;
    }
    final List<String> nodeIds = pathsByNode.get(nodeId);
    if (nodeIds == null) {
      throw new IOException("Reachable graph occurrence has no path from root: " + nodeId);
    }
    result.add(
        new MediatedGraphReport.ArtifactPath(
            kind,
            nodeId,
            coordinate,
            status.disposition(),
            status.protectionReason(),
            pathSteps(snapshot, nodeIds, projectGav)));
  }

  private static String pathKind(
      final EffectiveGraphDecisionIndex.DecisionKey key,
      final MediatedGraphReport.NodeStatus status,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> dropKeys,
      final Set<EffectiveGraphDecisionIndex.DecisionKey> trimKeys) {
    if (dropKeys.contains(key) && SAFE_ELIDED.equals(status.disposition())) {
      return DROPPED_KIND;
    }
    return trimKeys.contains(key) ? TRIMMED_KIND : null;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Insertion order preserves node-to-path mapping.
  private static List<MediatedGraphReport.PathStep> pathSteps(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<String> nodeIds,
      final String projectGav) {
    final Map<String, Map<String, Object>> nodesById = new LinkedHashMap<>();
    snapshot
        .nodes()
        .forEach(
            node ->
                nodesById.put(
                    (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID), node));
    return nodeIds.stream()
        .map(
            nodeId ->
                new MediatedGraphReport.PathStep(
                    nodeId,
                    MediatedGraphReportPathCoordinate.display(nodesById.get(nodeId), projectGav)))
        .toList();
  }

  private static Set<EffectiveGraphDecisionIndex.DecisionKey> decisionKeys(
      final Set<ArtifactCoordinate> coordinates) {
    final Set<EffectiveGraphDecisionIndex.DecisionKey> result = new HashSet<>();
    coordinates.stream().map(EffectiveGraphDecisionIndex.DecisionKey::of).forEach(result::add);
    return result;
  }

  private static Set<EffectiveGraphDecisionIndex.DecisionKey> trimKeys(
      final List<ArtifactTrimRecord> records) {
    final Set<EffectiveGraphDecisionIndex.DecisionKey> result = new HashSet<>();
    records.stream()
        .map(ArtifactTrimRecord::coordinate)
        .map(EffectiveGraphDecisionIndex.DecisionKey::of)
        .forEach(result::add);
    return result;
  }
}
