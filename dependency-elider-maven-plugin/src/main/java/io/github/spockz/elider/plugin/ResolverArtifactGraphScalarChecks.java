/* WHY: Keeps scalar field validation separate from graph object and topology checks. */

package io.github.spockz.elider.plugin;

import java.util.regex.Pattern;

/** Validates scalar values in detached graph payloads. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphScalarChecks {
  /** Restricts digest fields to the fixed-length SHA-256 representation. */
  private static final Pattern HASH_PATTERN = Pattern.compile("[0-9a-f]{64}");

  private ResolverArtifactGraphScalarChecks() {
    throw new AssertionError("No instances");
  }

  static String string(final Object value, final String field, final boolean nullable) {
    if (value instanceof String result) {
      return result;
    }
    if (nullable && value == null) {
      return null;
    }
    throw ResolverArtifactGraphPayloadChecks.invalid(
        field + " must be " + (nullable ? "a nullable string" : "a string"));
  }

  static String nodeId(final Object value, final String field) {
    final String result = string(value, field, false);
    if (!result.matches("n[0-9]+")) {
      throw ResolverArtifactGraphPayloadChecks.invalid(field + " is malformed");
    }
    return result;
  }

  static boolean bool(final Object value, final String field) {
    if (value instanceof Boolean result) {
      return result;
    }
    throw ResolverArtifactGraphPayloadChecks.invalid(field + " must be a boolean");
  }

  static Boolean nullableBoolean(final Object value, final String field) {
    if (value == null || value instanceof Boolean) {
      return (Boolean) value;
    }
    throw ResolverArtifactGraphPayloadChecks.invalid(field + " must be a nullable boolean");
  }

  static void integer(final Object value, final String field) {
    if (!(value instanceof Integer)) {
      throw ResolverArtifactGraphPayloadChecks.invalid(field + " must be an integer");
    }
  }

  static long longValue(final Object value, final String field, final boolean positive) {
    if (value instanceof Long result && result >= (positive ? 1L : 0L)) {
      return result;
    }
    throw ResolverArtifactGraphPayloadChecks.invalid(
        field + (positive ? " must be a positive long" : " must be a nonnegative long"));
  }

  static void requireHash(final String value, final String field) {
    if (!HASH_PATTERN.matcher(value).matches()) {
      throw ResolverArtifactGraphPayloadChecks.invalid(field + " must be a SHA-256 hex digest");
    }
  }
}
