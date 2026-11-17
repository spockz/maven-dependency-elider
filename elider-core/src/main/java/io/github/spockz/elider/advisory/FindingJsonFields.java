/* WHY: Shares strict JSON field checks for generic contributions and their cache container. */

package io.github.spockz.elider.advisory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.CacheProducerIdentity;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;

/** JSON shape primitives for the current generic finding format. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.GodClass", "PMD.TooManyMethods"})
final class FindingJsonFields {
  /** Complete fields of the plugin binary identity. */
  private static final Set<String> PRODUCER_FIELDS =
      Set.of("groupId", "artifactId", "version", "buildIdentity");

  private FindingJsonFields() {
    throw new AssertionError("No instances");
  }

  static JsonNode readSingleJsonDocument(
      final ObjectMapper mapper, final byte[] bytes, final String description) throws IOException {
    try (JsonParser parser = mapper.getFactory().createParser(bytes)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      final JsonNode root = mapper.readTree(parser);
      if (root == null || parser.nextToken() != null) {
        throw new IOException(description + " must contain exactly one JSON document");
      }
      return root;
    }
  }

  static JsonNode requiredArray(final JsonNode node, final String label) throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(label + " must be an array");
    }
    return node;
  }

  static void requireTextArray(final JsonNode node, final String label) throws IOException {
    for (final JsonNode value : requiredArray(node, label)) {
      if (!value.isTextual() || value.textValue().isBlank()) {
        throw new IOException(label + " must contain non-blank text");
      }
    }
  }

  static void requireShape(final JsonNode node, final Set<String> fields, final String label)
      throws IOException {
    requireObject(node, label);
    requireExactFields(node, fields, label);
  }

  static String requiredString(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual()) {
      throw new IOException(field + " must be text");
    }
    return value.textValue();
  }

  static String requiredText(final JsonNode node, final String field) throws IOException {
    final String value = requiredString(node, field);
    if (value.isBlank()) {
      throw new IOException(field + " must be non-blank text");
    }
    return value;
  }

  static String nullableText(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || (!value.isNull() && !value.isTextual())) {
      throw new IOException(field + " must be text or null");
    }
    return value.isNull() ? null : value.textValue();
  }

  static void requireObject(final JsonNode node, final String label) throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(label + " must be an object");
    }
  }

  static void requireExactFields(
      final JsonNode node, final Set<String> expected, final String label) throws IOException {
    final Set<String> actual = new HashSet<>();
    node.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(expected)) {
      final Set<String> missing = new java.util.TreeSet<>(expected);
      missing.removeAll(actual);
      final Set<String> unknown = new java.util.TreeSet<>(actual);
      unknown.removeAll(expected);
      throw new IOException(
          label
              + " fields do not match schema v1 (missing="
              + missing
              + ", unknown="
              + unknown
              + ")");
    }
  }

  static JsonNode readSchemaV1EnvelopeRoot(
      final ObjectMapper mapper,
      final InputStream input,
      final Set<String> rootFields,
      final String label)
      throws IOException {
    final JsonNode root;
    try (JsonParser parser = mapper.getFactory().createParser(input)) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      root = mapper.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException(label + " contains trailing JSON content");
      }
    }
    requireShape(root, rootFields, label);
    requireSchemaVersion(root, label);
    return root;
  }

  static void requireSchemaVersion(final JsonNode root, final String label) throws IOException {
    final JsonNode schema = root.get("schemaVersion");
    if (schema == null
        || !schema.isIntegralNumber()
        || !schema.canConvertToInt()
        || schema.intValue() != 1) {
      throw new IOException("Unsupported " + label + " schemaVersion");
    }
  }

  static CacheProducerIdentity readProducer(final JsonNode node, final String label)
      throws IOException {
    requireShape(node, PRODUCER_FIELDS, "producer");
    final String buildIdentity = nullableText(node, "buildIdentity");
    try {
      return new CacheProducerIdentity(
          requiredText(node, "groupId"),
          requiredText(node, "artifactId"),
          requiredText(node, "version"),
          buildIdentity);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid " + label + " producer identity", exception);
    }
  }

  static ObjectNode writeProducer(final ObjectMapper mapper, final CacheProducerIdentity producer) {
    final ObjectNode node = mapper.createObjectNode();
    node.put("groupId", producer.groupId());
    node.put("artifactId", producer.artifactId());
    node.put("version", producer.version());
    putNullable(node, "buildIdentity", producer.buildIdentity());
    return node;
  }

  static void putNullable(final ObjectNode node, final String field, final String value) {
    if (value == null) {
      node.putNull(field);
    } else {
      node.put(field, value);
    }
  }

  static <E extends Enum<E>> E enumValue(
      final String value, final Class<E> type, final String label) throws IOException {
    try {
      return Enum.valueOf(type, value);
    } catch (final IllegalArgumentException failure) {
      throw new IOException("Unsupported " + label + ": " + value, failure);
    }
  }

  static String describeFailure(final Throwable failure) {
    final StringBuilder description = new StringBuilder();
    appendFailure(
        description,
        failure,
        "",
        java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>()));
    return description.toString();
  }

  private static void appendFailure(
      final StringBuilder description,
      final Throwable failure,
      final String relation,
      final Set<Throwable> visited) {
    if (failure == null || !visited.add(failure)) {
      return;
    }
    if (!description.isEmpty()) {
      description.append("; ");
    }
    if (!relation.isEmpty()) {
      description.append(relation).append(": ");
    }
    final String message = failure.getMessage();
    description.append(
        message == null || message.isBlank() ? failure.getClass().getSimpleName() : message);
    for (final Throwable suppressed : failure.getSuppressed()) {
      appendFailure(description, suppressed, "suppressed", visited);
    }
    appendFailure(description, failure.getCause(), "caused by", visited);
  }
}
