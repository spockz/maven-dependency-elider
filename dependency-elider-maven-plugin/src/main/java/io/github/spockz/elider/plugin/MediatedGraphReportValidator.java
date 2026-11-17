/* WHY: Checks report provenance before detached path data is serialized. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import java.util.List;

/** Validates the node disposition records against their captured snapshot. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier") // Package-internal report validator.
final class MediatedGraphReportValidator {
  private MediatedGraphReportValidator() {
    throw new AssertionError("No instances");
  }

  static void validateAvailable(
      final String unavailableReason,
      final String captureToken,
      final String projectKey,
      final String beforeFingerprint,
      final ResolverArtifactGraphSnapshot snapshot,
      final List<MediatedGraphReport.NodeStatus> nodeStatuses,
      final List<MediatedGraphReport.ArtifactPath> artifactPaths) {
    validateProvenance(unavailableReason, captureToken, projectKey, beforeFingerprint, snapshot);
    ResolverArtifactGraphSnapshotPayloadValidator.validate(snapshot.toPayload(), projectKey);
    MediatedGraphReportNodeStatusValidator.validate(snapshot, nodeStatuses);
    MediatedGraphReportPathValidator.validate(snapshot, nodeStatuses, artifactPaths);
  }

  private static void validateProvenance(
      final String unavailableReason,
      final String captureToken,
      final String projectKey,
      final String beforeFingerprint,
      final ResolverArtifactGraphSnapshot snapshot) {
    if (!hasNoUnavailableReason(unavailableReason)
        || !hasCaptureToken(captureToken)
        || !hasProjectKey(projectKey, snapshot)
        || !hasBeforeFingerprint(beforeFingerprint)) {
      throw new IllegalArgumentException(
          "Available graph report provenance is incomplete: token="
              + captureToken
              + ", project="
              + projectKey
              + ", before="
              + beforeFingerprint
              + ", snapshotProject="
              + (snapshot == null ? null : snapshot.projectKey()));
    }
  }

  private static boolean hasNoUnavailableReason(final String reason) {
    return reason == null;
  }

  private static boolean hasCaptureToken(final String token) {
    return token != null && !token.isBlank();
  }

  private static boolean hasProjectKey(
      final String projectKey, final ResolverArtifactGraphSnapshot snapshot) {
    return projectKey != null && snapshot != null && projectKey.equals(snapshot.projectKey());
  }

  static void validateUnavailable(
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

  private static boolean hasBeforeFingerprint(final String fingerprint) {
    return HexDigest.isLowercaseHex(fingerprint, 64);
  }
}
