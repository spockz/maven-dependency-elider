/* WHY: Shares strict JSON field checks for generic contributions and their cache container. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** JSON shape primitives for the current generic finding format. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class FindingJsonFields {
  private FindingJsonFields() {
    throw new AssertionError("No instances");
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
      throw new IOException(label + " fields do not match schema v1");
    }
  }
}
