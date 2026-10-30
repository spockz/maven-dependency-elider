/* WHY: Keeps conditional class roots independent from deferred resource selection. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Validates resource descriptor conditions and retains their class names. */
final class NativeImageResourceCondition {
  private NativeImageResourceCondition() {}

  /* package */ static void read(
      final JsonNode condition, final Set<String> roots, final String name) throws IOException {
    final String conditionType = validateCondition(condition, name);
    roots.add(readClass(condition.get(conditionType), name));
  }

  private static String validateCondition(final JsonNode condition, final String name)
      throws IOException {
    if (!condition.isObject() || condition.size() != 1) {
      throw new IOException("Malformed native-image condition: " + name);
    }
    final String conditionType = condition.fieldNames().next();
    if (!"typeReachable".equals(conditionType) && !"typeReached".equals(conditionType)) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    return conditionType;
  }

  private static String readClass(final JsonNode className, final String name) throws IOException {
    if (className == null || !className.isTextual()) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    final String component = NativeImageTypeDescriptor.extractComponentClass(className.textValue());
    if (component == null
        || component.isEmpty()
        || !NativeImageDynamicRoots.isBinaryClassName(component)) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    return component;
  }
}
