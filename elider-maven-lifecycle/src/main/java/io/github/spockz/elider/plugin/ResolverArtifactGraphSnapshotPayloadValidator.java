/* WHY: Coordinates schema, node, topology, and fingerprint validation for
 * stored snapshots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.spockz.elider.model.HexDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Validates the detached graph snapshot envelope. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphSnapshotPayloadValidator {
  /** Keeps canonical JSON key ordering stable across Maven sessions. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

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
    validateFingerprint(fingerprint, root, nodesValue, edges);
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

  private static void validateFingerprint(
      final String expected, final Object rootNodeId, final List<?> nodes, final List<?> edges) {
    final Map<String, Object> structure = structure(rootNodeId, nodes, edges);
    try {
      final String json = JSON.writeValueAsString(structure);
      final String actual = fingerprint(json);
      if (!expected.equals(actual)) {
        throw ResolverArtifactGraphPayloadChecks.invalid(
            "graph fingerprint does not match snapshot data");
      }
    } catch (JsonProcessingException exception) {
      throw new IllegalStateException("Cannot serialize graph snapshot fingerprint", exception);
    }
  }

  // A linked map keeps canonical field order and accepts a null root ID.
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Object> structure(
      final Object rootNodeId, final List<?> nodes, final List<?> edges) {
    final Map<String, Object> structure = new LinkedHashMap<>();
    structure.put(ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID, rootNodeId);
    structure.put(ResolverArtifactGraphSnapshotSchema.NODES, nodes);
    structure.put(ResolverArtifactGraphSnapshotSchema.EDGES, edges);
    return structure;
  }

  private static String fingerprint(final String value) {
    return HexDigest.sha256(value);
  }
}
