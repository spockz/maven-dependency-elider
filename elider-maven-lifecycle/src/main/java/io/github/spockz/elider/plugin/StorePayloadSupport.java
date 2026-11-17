/* WHY: Shares strict JSON-decoded map, list, and scalar type checks across resolver stores. */

package io.github.spockz.elider.plugin;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shared validation helpers for deserialized store payloads. */
final class StorePayloadSupport {
  private StorePayloadSupport() {}

  /* package */ static Map<?, ?> requireMap(final Object value, final String field) {
    if (value instanceof Map<?, ?> result) {
      return result;
    }
    throw new IllegalStateException(field + " is not a map");
  }

  /* package */ static Map<String, Object> requireObjectMap(
      final Object value, final String field) {
    final Map<?, ?> raw = requireMap(value, field);
    final Map<String, Object> result = LinkedHashMap.newLinkedHashMap(raw.size());
    raw.forEach(
        (key, entry) -> {
          if (!(key instanceof String stringKey)) {
            throw new IllegalStateException(field + " contains a non-string key");
          }
          result.put(stringKey, entry);
        });
    return result;
  }

  /* package */ static List<?> requireList(final Object value, final String field) {
    if (value instanceof List<?> result) {
      return result;
    }
    throw new IllegalStateException(field + " is not a list");
  }

  /* package */ static String requireString(final Object value, final String field) {
    if (value instanceof String result) {
      return result;
    }
    throw new IllegalStateException(field + " is not a string");
  }

  /* package */ static String requireNonBlankString(final Object value, final String field) {
    if (value instanceof String text && !text.isBlank()) {
      return text;
    }
    throw new IllegalStateException(field + " must be a non-blank string");
  }

  /* package */ static long requireNonNegativeLong(final Object value, final String field) {
    if (value instanceof Long number && number >= 0L) {
      return number;
    }
    throw new IllegalStateException(field + " must be a non-negative integer");
  }

  /* package */ static boolean requireBoolean(final Object value, final String field) {
    if (value instanceof Boolean result) {
      return result;
    }
    throw new IllegalStateException(field + " must be a boolean");
  }
}
