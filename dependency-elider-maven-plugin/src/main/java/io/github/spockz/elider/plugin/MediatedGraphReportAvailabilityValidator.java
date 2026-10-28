/* WHY: Enforces the explicit no-graph state without reading unassigned record fields. */

package io.github.spockz.elider.plugin;

import java.util.List;

/** Validates that unavailable graph reports carry no capture data. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal report validation.
final class MediatedGraphReportAvailabilityValidator {
  private MediatedGraphReportAvailabilityValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(
      final String reason,
      final String captureToken,
      final String projectKey,
      final String beforeFingerprint,
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses,
      final List<MediatedGraphReport.ArtifactPath> artifactPaths) {
    if (reason == null || reason.isBlank()) {
      throw new IllegalArgumentException("Unavailable graph report requires a reason");
    }
    if (hasGraphData(
        captureToken, projectKey, beforeFingerprint, snapshot, nodeStatuses, artifactPaths)) {
      throw new IllegalArgumentException("Unavailable graph report cannot contain graph data");
    }
  }

  private static boolean hasGraphData(
      final String captureToken,
      final String projectKey,
      final String beforeFingerprint,
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses,
      final List<MediatedGraphReport.ArtifactPath> artifactPaths) {
    return captureToken != null
        || projectKey != null
        || beforeFingerprint != null
        || snapshot != null
        || !nodeStatuses.isEmpty()
        || !artifactPaths.isEmpty();
  }
}
