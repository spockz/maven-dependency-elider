// WHY: Shares exact JSON-shape checks across persisted report payload validators.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** Common strict shape checks for report JSON payloads. */
final class MavenElisionReportJsonPayloadShape {
  /** Standard prefix for strict persisted-report shape errors. */
  private static final String REPORT_PREFIX = "Elision report ";

  private MavenElisionReportJsonPayloadShape() {}

  /* default */ static void requireObject(
      final JsonNode node, final Set<String> expectedFields, final String label)
      throws IOException {
    if (node == null || !node.isObject() || !fieldNames(node).equals(expectedFields)) {
      throw new IOException(REPORT_PREFIX + label + " fields do not match schema version 1");
    }
  }

  /* default */ static void requireArray(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isArray()) {
      throw new IOException(REPORT_PREFIX + field + " must be an array");
    }
  }

  /* default */ static void requireBoolean(final JsonNode node, final String field)
      throws IOException {
    if (node == null || !node.isBoolean()) {
      throw new IOException(REPORT_PREFIX + field + " must be a JSON boolean");
    }
  }

  /* default */ static void requireText(
      final JsonNode node, final String field, final String pattern) throws IOException {
    if (node == null || !node.isTextual() || !node.textValue().matches(pattern)) {
      throw new IOException(REPORT_PREFIX + field + " has an invalid value");
    }
  }

  /* default */ static void optionalText(final JsonNode node, final String field)
      throws IOException {
    if (node != null && !node.isNull() && !node.isTextual()) {
      throw new IOException(REPORT_PREFIX + field + " must be text or null");
    }
  }

  /* default */ static void stringArray(final JsonNode node, final String field)
      throws IOException {
    requireArray(node, field);
    for (final JsonNode value : node) {
      requireText(value, field + " item", ".+");
    }
  }

  private static Set<String> fieldNames(final JsonNode node) {
    final Set<String> names = new HashSet<>();
    final Iterator<String> fields = node.fieldNames();
    fields.forEachRemaining(names::add);
    return names;
  }
}
