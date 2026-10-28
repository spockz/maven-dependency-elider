// WHY: Protects graph primitives from coercion before the report's record binding.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** Validates the persisted mediated graph envelope and primitive snapshot fields. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.CommentRequired"})
final class MavenElisionReportGraphPayloadValidator {
  private static final String AVAILABLE = "available";
  private static final String UNAVAILABLE_REASON = "unavailableReason";
  private static final String CAPTURE_TOKEN = "captureToken";
  private static final String PROJECT_KEY = ResolverArtifactGraphSnapshotSchema.PROJECT_KEY;
  private static final String BEFORE_FINGERPRINT = "beforeFingerprint";
  private static final String SNAPSHOT = "snapshot";
  private static final String NODE_STATUSES = "nodeStatuses";
  private static final String ARTIFACT_PATHS = "artifactPaths";
  private static final String PLAN_PRESENT = ResolverArtifactGraphSnapshotSchema.PLAN_PRESENT;
  private static final String PLAN_FINGERPRINT =
      ResolverArtifactGraphSnapshotSchema.PLAN_FINGERPRINT;
  private static final String PLAN_GENERATION = ResolverArtifactGraphSnapshotSchema.PLAN_GENERATION;
  private static final String CAPTURE_GENERATION =
      ResolverArtifactGraphSnapshotSchema.CAPTURE_GENERATION;
  private static final String GRAPH_FINGERPRINT =
      ResolverArtifactGraphSnapshotSchema.GRAPH_FINGERPRINT;
  private static final String ROOT_NODE_ID = ResolverArtifactGraphSnapshotSchema.ROOT_NODE_ID;
  private static final String NODES = ResolverArtifactGraphSnapshotSchema.NODES;
  private static final String EDGES = ResolverArtifactGraphSnapshotSchema.EDGES;
  private static final Set<String> ENVELOPE_FIELDS =
      Set.of(
          AVAILABLE,
          UNAVAILABLE_REASON,
          CAPTURE_TOKEN,
          PROJECT_KEY,
          BEFORE_FINGERPRINT,
          SNAPSHOT,
          NODE_STATUSES,
          ARTIFACT_PATHS);
  private static final Set<String> SNAPSHOT_FIELDS =
      ResolverArtifactGraphSnapshotSchema.SNAPSHOT_FIELDS;

  private MavenElisionReportGraphPayloadValidator() {}

  static void validate(final JsonNode graph) throws IOException {
    requireExactObject(graph, ENVELOPE_FIELDS, "mediated graph");
    requireBoolean(graph, AVAILABLE, "availability");
    for (final String field :
        Set.of(UNAVAILABLE_REASON, CAPTURE_TOKEN, PROJECT_KEY, BEFORE_FINGERPRINT)) {
      requireNullableText(graph, field);
    }
    validateSnapshot(graph.get(SNAPSHOT));
    requireArray(graph, NODE_STATUSES, "mediated graph rows");
    requireArray(graph, ARTIFACT_PATHS, "mediated graph rows");
  }

  private static void validateSnapshot(final JsonNode snapshot) throws IOException {
    if (snapshot == null || snapshot.isNull()) {
      return;
    }
    requireExactObject(snapshot, SNAPSHOT_FIELDS, "graph snapshot");
    requireBoolean(snapshot, PLAN_PRESENT, PLAN_PRESENT);
    requireNonnegativeLong(snapshot, PLAN_GENERATION);
    requireNonnegativeLong(snapshot, CAPTURE_GENERATION);
    requireNonblankText(snapshot, GRAPH_FINGERPRINT);
    requireNonblankText(snapshot, PROJECT_KEY);
    requireNullableText(snapshot, PLAN_FINGERPRINT);
    requireNonblankText(snapshot, ROOT_NODE_ID);
    requireArray(snapshot, NODES, "graph snapshot nodes and edges");
    requireArray(snapshot, EDGES, "graph snapshot nodes and edges");
  }

  private static void requireExactObject(
      final JsonNode value, final Set<String> fields, final String label) throws IOException {
    if (value == null || !value.isObject() || !fieldNames(value).equals(fields)) {
      throw new IOException("Elision report " + label + " fields do not match schema version 1");
    }
  }

  private static void requireBoolean(final JsonNode value, final String field, final String label)
      throws IOException {
    if (!value.path(field).isBoolean()) {
      throw new IOException("Elision report graph " + label + " must be boolean");
    }
  }

  private static void requireNonnegativeLong(final JsonNode value, final String field)
      throws IOException {
    final JsonNode number = value.get(field);
    if (number == null
        || !number.isIntegralNumber()
        || !number.canConvertToLong()
        || number.longValue() < 0) {
      throw new IOException("Elision report graph field must be a nonnegative integer: " + field);
    }
  }

  private static void requireNonblankText(final JsonNode value, final String field)
      throws IOException {
    final JsonNode text = value.get(field);
    if (text == null || !text.isTextual() || text.textValue().isBlank()) {
      throw new IOException("Elision report graph field must be nonblank text: " + field);
    }
  }

  private static void requireNullableText(final JsonNode value, final String field)
      throws IOException {
    final JsonNode text = value.get(field);
    if (text == null || (!text.isNull() && !text.isTextual())) {
      throw new IOException("Elision report graph field must be text or null: " + field);
    }
  }

  private static void requireArray(final JsonNode value, final String field, final String label)
      throws IOException {
    if (!value.path(field).isArray()) {
      throw new IOException("Elision report " + label + " must be arrays");
    }
  }

  private static Set<String> fieldNames(final JsonNode value) {
    final Set<String> fields = new HashSet<>();
    value.fieldNames().forEachRemaining(fields::add);
    return fields;
  }
}
