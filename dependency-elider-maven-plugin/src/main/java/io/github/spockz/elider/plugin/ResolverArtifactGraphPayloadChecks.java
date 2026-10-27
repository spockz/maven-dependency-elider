/* WHY: Centralizes primitive type checks used by graph payload validators. */

package io.github.spockz.elider.plugin;

import java.util.Map;
import java.util.Set;

/** Small type and exact-field checks for detached graph values. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ResolverArtifactGraphPayloadChecks {
  private ResolverArtifactGraphPayloadChecks() {
    throw new AssertionError("No instances");
  }

  static void fields(final Map<?, ?> value, final Set<String> expected, final String subject) {
    if (!value.keySet().equals(expected)) {
      throw invalid(subject + " fields do not match the schema");
    }
    value
        .keySet()
        .forEach(
            key -> ResolverArtifactGraphScalarChecks.string(key, subject + " field name", false));
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

  static IllegalStateException invalid(final String detail) {
    return new IllegalStateException("Invalid graph snapshot payload: " + detail);
  }
}
