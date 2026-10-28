/* WHY: Turns graph policy outcomes into one detached status for every captured node. */

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Map;

/** Builds per-node dispositions and protection reasons for the report. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal outcome construction API.
final class MediatedGraphReportOutcomeBuilder {
  /** Status for conflict-winner metadata nodes without root reachability. */
  private static final String METADATA_ONLY = "METADATA_ONLY";

  private MediatedGraphReportOutcomeBuilder() {
    throw new AssertionError("No instances");
  }

  static List<MediatedGraphReport.NodeStatus> nodeStatuses(
      final ResolverArtifactGraphSnapshot snapshot,
      final EffectiveGraphPolicy.Evaluation evaluation) {
    return snapshot.nodes().stream()
        .map(
            node -> {
              final String nodeId = (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
              final boolean reachable =
                  Boolean.TRUE.equals(node.get(ResolverArtifactGraphSnapshotSchema.REACHABLE));
              final EffectiveGraphPolicy.NodeDisposition disposition =
                  evaluation.nodeDispositions().get(nodeId);
              final String status =
                  reachable
                      ? java.util.Objects.requireNonNull(disposition, "reachable node disposition")
                          .name()
                      : METADATA_ONLY;
              return new MediatedGraphReport.NodeStatus(
                  nodeId, status, protectionReason(node, evaluation));
            })
        .toList();
  }

  private static String protectionReason(
      final Map<String, Object> node, final EffectiveGraphPolicy.Evaluation evaluation) {
    final EffectiveGraphDecisionIndex.Gavce identity = EffectiveGraphDecisionIndex.gavce(node);
    final String scope = (String) node.get(ResolverArtifactGraphSnapshotSchema.EFFECTIVE_SCOPE);
    if (identity == null || scope == null) {
      return null;
    }
    return evaluation.protectedReasons().entrySet().stream()
        .filter(entry -> EffectiveGraphDecisionIndex.Gavce.of(entry.getKey()).equals(identity))
        .filter(entry -> entry.getKey().scope().equals(scope))
        .map(Map.Entry::getValue)
        .findFirst()
        .orElse(null);
  }
}
