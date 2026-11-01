// WHY: Shares strict scalar and collection checks between report advisory row validators.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/** Common validators for advisory review payload values. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportAdvisoryPayloadSupport {
  /** Prefix for validation diagnostics. */
  private static final String REPORT_PREFIX = "Elision report ";

  private MavenElisionReportAdvisoryPayloadSupport() {}

  static Set<String> fieldNames(final JsonNode object) {
    final Set<String> names = new HashSet<>();
    object.fieldNames().forEachRemaining(names::add);
    return names;
  }

  static void requireFields(final JsonNode object, final Set<String> expected, final String message)
      throws IOException {
    if (object == null || !object.isObject() || !fieldNames(object).equals(expected)) {
      throw new IOException(message);
    }
  }

  static void text(final JsonNode value, final String field) throws IOException {
    if (value == null || !value.isTextual() || value.textValue().isBlank()) {
      throw new IOException(REPORT_PREFIX + field + " must be non-blank text");
    }
  }

  static void nullableText(final JsonNode value, final String field) throws IOException {
    if (value == null || (!value.isNull() && !value.isTextual())) {
      throw new IOException(REPORT_PREFIX + field + " must be text or null");
    }
  }

  static void stringArray(final JsonNode values, final String field) throws IOException {
    if (values == null || !values.isArray()) {
      throw new IOException(REPORT_PREFIX + field + " must be an array");
    }
    for (final JsonNode value : values) {
      text(value, field + " item");
    }
  }

  static void enumValue(final JsonNode value, final Set<String> allowed, final String field)
      throws IOException {
    if (value == null || !value.isTextual() || !allowed.contains(value.textValue())) {
      throw new IOException(REPORT_PREFIX + field + " is unsupported");
    }
  }

  static void optionalSha(final JsonNode value, final String field) throws IOException {
    if (value == null || value.isNull()) {
      return;
    }
    if (!value.isTextual() || !value.textValue().matches("[0-9a-f]{64}")) {
      throw new IOException(field + " must be null or a lowercase SHA-256");
    }
  }

  static void nullableCve(final JsonNode value) throws IOException {
    if (value == null || value.isNull()) {
      return;
    }
    if (!value.isTextual() || !value.textValue().matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IOException("Elision report heuristic cveId must be null or a CVE identifier");
    }
  }

  static void coordinate(final JsonNode value) throws IOException {
    MavenElisionReportSourceCoordinateValidator.validate(value);
  }

  static void validateTextEvent(final JsonNode event) throws IOException {
    if (!event.isObject() || event.isEmpty()) {
      throw new IOException("Elision report package range event must be a non-empty object");
    }
    final Iterator<JsonNode> values = event.elements();
    while (values.hasNext()) {
      text(values.next(), "package range event value");
    }
  }
}
