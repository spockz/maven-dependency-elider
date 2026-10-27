/* WHY: Centralizes primitive type checks used by graph payload validators. */

package io.github.spockz.elider.plugin;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Small type and exact-field checks for detached graph values. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphPayloadChecks {
  /** Restricts digest fields to the fixed-length SHA-256 representation. */
  private static final Pattern HASH_PATTERN = Pattern.compile("[0-9a-f]{64}");

  private ResolverArtifactGraphPayloadChecks() {
    throw new AssertionError("No instances");
  }

  static void fields(final Map<?, ?> value, final Set<String> expected, final String subject) {
    if (!value.keySet().equals(expected)) {
      throw invalid(subject + " fields do not match the schema");
    }
    value.keySet().forEach(key -> string(key, subject + " field name", false));
  }

  static Map<?, ?> map(final Object value, final String field) {
    if (value instanceof Map<?, ?> result) {
      return result;
    }
    throw invalid(field + " must be a map");
  }

  static java.util.List<?> list(final Object value, final String field) {
    if (value instanceof java.util.List<?> result) {
      return result;
    }
    throw invalid(field + " must be a list");
  }

  static String string(final Object value, final String field, final boolean nullable) {
    if (value instanceof String result) {
      return result;
    }
    if (nullable && value == null) {
      return null;
    }
    throw invalid(field + " must be " + (nullable ? "a nullable string" : "a string"));
  }

  static String nodeId(final Object value, final String field) {
    final String result = string(value, field, false);
    if (!result.matches("n[0-9]+")) {
      throw invalid(field + " is malformed");
    }
    return result;
  }

  static boolean bool(final Object value, final String field) {
    if (value instanceof Boolean result) {
      return result;
    }
    throw invalid(field + " must be a boolean");
  }

  static void integer(final Object value, final String field) {
    if (!(value instanceof Integer)) {
      throw invalid(field + " must be an integer");
    }
  }

  static long longValue(final Object value, final String field, final boolean positive) {
    if (value instanceof Long result && result >= (positive ? 1L : 0L)) {
      return result;
    }
    throw invalid(field + (positive ? " must be a positive long" : " must be a nonnegative long"));
  }

  static void requireHash(final String value, final String field) {
    if (!HASH_PATTERN.matcher(value).matches()) {
      throw invalid(field + " must be a SHA-256 hex digest");
    }
  }

  static IllegalStateException invalid(final String detail) {
    return new IllegalStateException("Invalid graph snapshot payload: " + detail);
  }
}
