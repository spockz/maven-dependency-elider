/* WHY: Verifies path labels and output meanings against their captured graph occurrences. */

package io.github.spockz.elider.plugin;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Checks graph path coordinates, node outcomes, and canonical shortest walks. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Package-internal semantic validation helper.
final class MediatedGraphReportPathSemanticValidator {
  /** Path classification for a whole-artifact drop. */
  private static final String DROPPED_KIND = "WHOLE_ARTIFACT_DROPPED";

  /** Path classification for class-level trimming. */
  private static final String TRIMMED_KIND = "CLASS_TRIMMED";

  /** Disposition required for an effective whole-artifact drop. */
  private static final String SAFE_ELIDED = "SAFE_ELIDED";

  /** Nonreachable metadata nodes cannot own output paths. */
  private static final String METADATA_ONLY = "METADATA_ONLY";

  private MediatedGraphReportPathSemanticValidator() {
    throw new AssertionError("No instances");
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // These indexes are local to one validation call.
  static Context context(
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses) {
    final Map<String, Map<String, Object>> nodesById = new HashMap<>();
    snapshot.nodes().forEach(node -> nodesById.put(nodeId(node), node));
    final Map<String, MediatedGraphReport.NodeStatus> statusesById = new HashMap<>();
    nodeStatuses.forEach(status -> statusesById.put(status.nodeId(), status));
    return new Context(nodesById, statusesById, MediatedGraphShortestPaths.from(snapshot));
  }

  static void validatePath(
      final Context context, final String projectGav, final MediatedGraphReport.ArtifactPath path) {
    validatePathMeaning(context, path);
    validateCanonicalPath(context, projectGav, path);
  }

  private static void validatePathMeaning(
      final Context context, final MediatedGraphReport.ArtifactPath path) {
    final Map<String, Object> node = context.nodesById().get(path.nodeId());
    final MediatedGraphReport.NodeStatus status = context.statusesById().get(path.nodeId());
    validateCoordinateAndStatus(node, status, path);
    validateOutputKind(status, path);
  }

  private static void validateCoordinateAndStatus(
      final Map<String, Object> node,
      final MediatedGraphReport.NodeStatus status,
      final MediatedGraphReport.ArtifactPath path) {
    if (node == null
        || status == null
        || !path.coordinate().equals(MediatedGraphReportPathCoordinate.coordinate(node))
        || !path.disposition().equals(status.disposition())
        || !java.util.Objects.equals(path.protectionReason(), status.protectionReason())) {
      throw new IllegalArgumentException("Graph report path disagrees with its node outcome");
    }
  }

  private static void validateOutputKind(
      final MediatedGraphReport.NodeStatus status, final MediatedGraphReport.ArtifactPath path) {
    final String kind = path.kind();
    final String disposition = status.disposition();
    switch (kind) {
      case DROPPED_KIND -> validateDroppedDisposition(disposition);
      case TRIMMED_KIND -> validateTrimmedDisposition(disposition);
      default -> throw new IllegalArgumentException("Graph report path has an unknown output kind");
    }
  }

  private static void validateDroppedDisposition(final String disposition) {
    if (!SAFE_ELIDED.equals(disposition)) {
      throw new IllegalArgumentException("Dropped path does not have SAFE_ELIDED disposition");
    }
  }

  private static void validateTrimmedDisposition(final String disposition) {
    if (SAFE_ELIDED.equals(disposition) || METADATA_ONLY.equals(disposition)) {
      throw new IllegalArgumentException("Trimmed path has an incompatible disposition");
    }
  }

  private static void validateCanonicalPath(
      final Context context, final String projectGav, final MediatedGraphReport.ArtifactPath path) {
    final List<String> expected = context.canonicalPaths().get(path.nodeId());
    final List<String> actual =
        path.steps().stream().map(MediatedGraphReport.PathStep::nodeId).toList();
    if (expected == null || !expected.equals(actual)) {
      throw new IllegalArgumentException("Graph report path is not the canonical shortest path");
    }
    validateStepLabels(context, projectGav, path);
  }

  private static void validateStepLabels(
      final Context context, final String projectGav, final MediatedGraphReport.ArtifactPath path) {
    for (final MediatedGraphReport.PathStep step : path.steps()) {
      final String expected =
          MediatedGraphReportPathCoordinate.display(
              context.nodesById().get(step.nodeId()), projectGav);
      if (expected != null && !expected.equals(step.coordinate())) {
        throw new IllegalArgumentException("Graph report path step coordinate is forged");
      }
    }
  }

  private static String nodeId(final Map<String, Object> node) {
    return (String) node.get(ResolverArtifactGraphSnapshotSchema.NODE_ID);
  }

  record Context(
      Map<String, Map<String, Object>> nodesById,
      Map<String, MediatedGraphReport.NodeStatus> statusesById,
      Map<String, List<String>> canonicalPaths) {}
}
