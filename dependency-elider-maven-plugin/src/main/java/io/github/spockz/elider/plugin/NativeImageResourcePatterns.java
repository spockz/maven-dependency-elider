/* WHY: Extracts class roots from native-image resource conditions without
 * guessing unknown forms. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads resource patterns and their supported conditional class roots. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageResourcePatterns {
  private NativeImageResourcePatterns() {}

  static void read(final JsonNode patterns, final Set<String> roots, final String name)
      throws IOException {
    for (final JsonNode pattern : patterns) {
      final JsonNode value = pattern.get("pattern");
      if (!pattern.isObject() || value == null || !value.isTextual()) {
        throw new IOException("Malformed native-image resource pattern: " + name);
      }
      final JsonNode condition = pattern.get("condition");
      if (condition != null) {
        readCondition(condition, roots, name);
      }
    }
  }

  static void readCondition(final JsonNode condition, final Set<String> roots, final String name)
      throws IOException {
    if (!condition.isObject() || condition.size() != 1) {
      throw new IOException("Malformed native-image condition: " + name);
    }
    final String conditionType = condition.fieldNames().next();
    final JsonNode className = condition.get(conditionType);
    if (!"typeReached".equals(conditionType)
        || !className.isTextual()
        || !NativeImageDynamicRoots.isBinaryClassName(className.textValue())) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    roots.add(className.textValue());
  }
}
