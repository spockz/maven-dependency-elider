/* WHY: Shares strict schema-shape checks across prediction JSON decoding. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.List;
import java.util.Set;

@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MavenElisionReportPredictionJson {
  private static final String ROOT = "prerequisitePrediction";

  private MavenElisionReportPredictionJson() {}

  static void shape(final JsonNode node, final Set<String> fields, final String path)
      throws IOException {
    if (!node.isObject()) {
      throw new IOException(path + " must be an object");
    }
    final Set<String> actual = new java.util.HashSet<>();
    node.fieldNames().forEachRemaining(actual::add);
    if (!actual.equals(fields)) {
      throw new IOException(path + " fields are invalid: " + actual);
    }
  }

  static List<JsonNode> array(final JsonNode parent, final String field, final String path) {
    final JsonNode value = parent.get(field);
    if (value == null || !value.isArray()) {
      throw new IllegalArgumentException(path + " must be an array");
    }
    return java.util.stream.StreamSupport.stream(value.spliterator(), false).toList();
  }

  static String text(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(ROOT + "." + field + " must be nonblank text");
    }
    return value.textValue();
  }

  static String nullableText(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || value.isNull()) {
      return null;
    }
    if (!value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(ROOT + "." + field + " must be null or nonblank text");
    }
    return value.textValue();
  }

  static boolean bool(final JsonNode node, final String field) throws IOException {
    final JsonNode value = node.get(field);
    if (value == null || !value.isBoolean()) {
      throw new IOException(ROOT + "." + field + " must be boolean");
    }
    return value.booleanValue();
  }

  static <E extends Enum<E>> E enumValue(
      final JsonNode node, final String field, final Class<E> type) throws IOException {
    final String value = text(node, field);
    try {
      return Enum.valueOf(type, value);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(ROOT + "." + field + " is unknown", exception);
    }
  }
}
