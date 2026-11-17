// WHY: Shares exact JSON-shape checks across persisted report payload validators.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.StreamSupport;

/** Common strict shape checks for report JSON payloads. */
@SuppressWarnings({"PMD.GodClass", "PMD.TooManyMethods"})
final class MavenElisionReportJsonPayloadShape {
  /** Standard prefix for strict persisted-report shape errors. */
  private static final String REPORT_PREFIX = "Elision report ";

  /** Standard prefix for prerequisite prediction shape errors. */
  private static final String PREDICTION_ROOT = "prerequisitePrediction";

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

  /* default */ static Set<String> fieldNames(final JsonNode node) {
    final Set<String> names = new HashSet<>();
    final Iterator<String> fields = node.fieldNames();
    fields.forEachRemaining(names::add);
    return names;
  }

  /* default */ static void shape(final JsonNode node, final Set<String> fields, final String path)
      throws IOException {
    if (node == null || !node.isObject()) {
      throw new IOException(path + " must be an object");
    }
    final Set<String> actual = fieldNames(node);
    if (!actual.equals(fields)) {
      throw new IOException(path + " fields are invalid: " + actual);
    }
  }

  /* default */ static List<JsonNode> array(
      final JsonNode parent, final String field, final String path) {
    final JsonNode value = parent.get(field);
    if (value == null || !value.isArray()) {
      throw new IllegalArgumentException(path + " must be an array");
    }
    return StreamSupport.stream(value.spliterator(), false).toList();
  }

  /* default */ static String text(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(PREDICTION_ROOT + "." + field + " must be nonblank text");
    }
    return value.textValue();
  }

  /* default */ static String nullableText(final JsonNode node, final String field)
      throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(PREDICTION_ROOT + "." + field + " must be null or nonblank text");
    }
    return value.textValue();
  }

  /* default */ static boolean bool(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isBoolean()) {
      throw new IOException(PREDICTION_ROOT + "." + field + " must be boolean");
    }
    return value.booleanValue();
  }

  /* default */ static <E extends Enum<E>> E enumValue(
      final JsonNode node, final String field, final Class<E> type) throws IOException {
    return enumName(text(node, field), type, PREDICTION_ROOT + "." + field + " is unknown");
  }

  /* default */ static <E extends Enum<E>> E enumName(
      final String name, final Class<E> type, final String errorMessage) throws IOException {
    try {
      return Enum.valueOf(type, name);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(errorMessage, exception);
    }
  }
}
