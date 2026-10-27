/* WHY: Coordinates schema, node, topology, and fingerprint validation for stored snapshots. */

package io.github.spockz.elider.plugin;

import java.util.List;
import java.util.Map;

/** Validates the detached graph snapshot envelope. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphSnapshotPayloadValidator {
  private ResolverArtifactGraphSnapshotPayloadValidator() {
    throw new AssertionError("No instances");
  }

  static void validate(final Map<String, Object> snapshot, final String expectedProjectKey) {
    ResolverArtifactGraphPayloadChecks.fields(
        snapshot, ResolverArtifactGraphSnapshotSchema.SNAPSHOT_FIELDS, "snapshot");
    validateProject(snapshot, expectedProjectKey);
    final String fingerprint =
        ResolverArtifactGraphPayloadChecks.string(
            snapshot.get(ResolverArtifactGraphSnapshotSchema.GRAPH_FINGERPRINT),
            "graph fingerprint",
            false);
    ResolverArtifactGraphPayloadChecks.requireHash(fingerprint, "graph fingerprint");
    validatePlanProvenance(snapshot);
    ResolverArtifactGraphPayloadChecks.longValue(
        snapshot.get(ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION),
        "plan generation",
        false);
    ResolverArtifactGraphPayloadChecks.longValue(
        snapshot.get(ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION),
        "capture generation",
        true);
    final List<?> nodesValue =
        ResolverArtifactGraphPayloadChecks.list(
            snapshot.get(ResolverArtifactGraphSnapshotSchema.NODES),
            ResolverArtifactGraphSnapshotSchema.NODES);
    final Map<String, Map<?, ?>> nodes = ResolverArtifactNodePayloadValidator.validate(nodesValue);
    final Object root = snapshot.get(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID);
    final List<?> edges =
        ResolverArtifactGraphPayloadChecks.list(
            snapshot.get(ResolverArtifactGraphSnapshotSchema.EDGES),
            ResolverArtifactGraphSnapshotSchema.EDGES);
    ResolverArtifactTopologyPayloadValidator.validate(root, edges, nodes);
    ResolverArtifactGraphFingerprintValidator.validate(fingerprint, root, nodesValue, edges);
  }

  private static void validateProject(
      final Map<String, Object> snapshot, final String expectedProjectKey) {
    final String projectKey =
        ResolverArtifactGraphPayloadChecks.string(
            snapshot.get(ResolverArtifactGraphSnapshotSchema.PROJECT_KEY),
            "snapshot project key",
            false);
    if (!expectedProjectKey.equals(projectKey)) {
      throw ResolverArtifactGraphPayloadChecks.invalid(
          "snapshot project key does not match its store key");
    }
  }

  private static void validatePlanProvenance(final Map<String, Object> snapshot) {
    final boolean present =
        ResolverArtifactGraphPayloadChecks.bool(
            snapshot.get(ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT), "plan presence");
    final Object fingerprint = snapshot.get(ResolverArtifactGraphSnapshotSchema.PLAN_FINGERPRINT);
    if (fingerprint != null) {
      final String value =
          ResolverArtifactGraphPayloadChecks.string(fingerprint, "plan fingerprint", false);
      ResolverArtifactGraphPayloadChecks.requireHash(value, "plan fingerprint");
    }
    if (present != (fingerprint != null)) {
      throw ResolverArtifactGraphPayloadChecks.invalid("plan presence and fingerprint disagree");
    }
  }
}
