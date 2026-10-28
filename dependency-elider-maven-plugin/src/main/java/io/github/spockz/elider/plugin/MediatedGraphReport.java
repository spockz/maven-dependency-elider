/* WHY: Stores occurrence-aware mediated paths with the elision outcomes used to publish them. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Detached graph, outcome, and shortest-path data persisted by the elide report. */
@SuppressWarnings(
    "PMD.CommentDefaultAccessModifier") // Record fields are the internal report schema.
record MediatedGraphReport(
    boolean available,
    String unavailableReason,
    String captureToken,
    String projectKey,
    String beforeFingerprint,
    ResolverArtifactGraphSnapshot snapshot,
    List<NodeStatus> nodeStatuses,
    List<ArtifactPath> artifactPaths) {
  /** Used when no compatible resolver capture can be tied to the analysis. */
  private static final String NO_GRAPH_REASON = "No compatible mediated graph was captured";

  MediatedGraphReport {
    nodeStatuses = List.copyOf(Objects.requireNonNull(nodeStatuses, "nodeStatuses"));
    artifactPaths = List.copyOf(Objects.requireNonNull(artifactPaths, "artifactPaths"));
    if (available) {
      MediatedGraphReportValidator.validateAvailable(
          unavailableReason,
          captureToken,
          projectKey,
          beforeFingerprint,
          snapshot,
          nodeStatuses,
          artifactPaths);
    } else {
      MediatedGraphReportAvailabilityValidator.validate(
          unavailableReason,
          captureToken,
          projectKey,
          beforeFingerprint,
          snapshot,
          nodeStatuses,
          artifactPaths);
    }
  }

  static MediatedGraphReport unavailable(final String reason) {
    return new MediatedGraphReport(
        false,
        reason == null || reason.isBlank() ? NO_GRAPH_REASON : reason,
        null,
        null,
        null,
        null,
        List.of(),
        List.of());
  }

  static MediatedGraphReport create(
      final ResolverArtifactGraphCapturePair pair,
      final EffectiveGraphPolicy.Evaluation evaluation,
      final Set<ArtifactCoordinate> effectiveDrops,
      final List<ArtifactTrimRecord> trimRecords,
      final String projectGav)
      throws IOException {
    if (pair == null) {
      return unavailable(evaluation == null ? NO_GRAPH_REASON : evaluation.failClosedReason());
    }
    if (evaluation == null || evaluation.failClosed()) {
      throw new IOException("Bound graph report is missing a successful policy evaluation");
    }
    validateSnapshot(pair);
    return createValidated(pair, evaluation, effectiveDrops, trimRecords, projectGav);
  }

  private static void validateSnapshot(final ResolverArtifactGraphCapturePair pair)
      throws IOException {
    try {
      ResolverArtifactGraphSnapshotPayloadValidator.validate(
          pair.after().toPayload(), pair.projectKey());
    } catch (final IllegalArgumentException | IllegalStateException exception) {
      throw new IOException("Bound mediated graph report is invalid", exception);
    }
  }

  private static MediatedGraphReport createValidated(
      final ResolverArtifactGraphCapturePair pair,
      final EffectiveGraphPolicy.Evaluation evaluation,
      final Set<ArtifactCoordinate> effectiveDrops,
      final List<ArtifactTrimRecord> trimRecords,
      final String projectGav)
      throws IOException {
    final ResolverArtifactGraphSnapshot snapshot = pair.after();
    final List<NodeStatus> statuses =
        MediatedGraphReportOutcomeBuilder.nodeStatuses(snapshot, evaluation);
    final List<ArtifactPath> paths =
        MediatedGraphReportPathBuilder.build(
            snapshot, statuses, effectiveDrops, trimRecords, projectGav);
    MediatedGraphReportCoverageValidator.validate(paths, effectiveDrops, trimRecords);
    return new MediatedGraphReport(
        true,
        null,
        pair.captureToken(),
        pair.projectKey(),
        pair.before().graphFingerprint(),
        snapshot,
        statuses,
        paths);
  }

  record NodeStatus(String nodeId, String disposition, String protectionReason) {
    NodeStatus {
      if (nodeId == null || nodeId.isBlank() || disposition == null || disposition.isBlank()) {
        throw new IllegalArgumentException("Graph node status is incomplete");
      }
    }
  }

  record ArtifactPath(
      String kind,
      String nodeId,
      ArtifactCoordinate coordinate,
      String disposition,
      String protectionReason,
      List<PathStep> steps) {
    ArtifactPath {
      if (kind == null || nodeId == null || coordinate == null || disposition == null) {
        throw new IllegalArgumentException("Graph artifact path is incomplete");
      }
      steps = List.copyOf(Objects.requireNonNull(steps, "steps"));
    }
  }

  record PathStep(String nodeId, String coordinate) {
    PathStep {
      if (nodeId == null || coordinate == null || coordinate.isBlank()) {
        throw new IllegalArgumentException("Graph path step is incomplete");
      }
    }
  }
}
