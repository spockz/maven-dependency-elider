/* WHY: Shares class and condition roots across legacy and unified descriptors. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Extracts common positive roots from class-bearing descriptor fields. */
final class NativeImageRootSupport {
  /** WHY: Unified conditions use only this selector. */
  private static final String TYPE_REACHED = "typeReached";

  /** WHY: Standalone conditions also accept the legacy selector. */
  private static final String TYPE_REACHABLE = "typeReachable";

  private NativeImageRootSupport() {}

  /* package */
  static void readCondition(
      final JsonNode condition, final String name, final Set<String> roots, final boolean unified)
      throws IOException {
    if (condition == null) {
      return;
    }
    NativeImageJsonSupport.requireObject(condition, "condition", name);
    NativeImageJsonSupport.validateFields(
        condition,
        unified ? Set.of(TYPE_REACHED) : Set.of(TYPE_REACHED, TYPE_REACHABLE),
        "condition",
        name);
    final boolean hasReached = condition.has(TYPE_REACHED);
    final boolean hasReachable = condition.has(TYPE_REACHABLE);
    if (hasReached == hasReachable) {
      throw new IOException("Malformed native-image condition: " + name);
    }
    final JsonNode type = hasReached ? condition.get(TYPE_REACHED) : condition.get(TYPE_REACHABLE);
    if (unified) {
      NativeImageUnifiedReflectionConfig.addType(type, name, roots);
      return;
    }
    NativeImageJsonSupport.requireText(type, "condition class name", name);
    final String className = type.textValue();
    if (!NativeImageDynamicRoots.isBinaryClassName(className)) {
      throw new IOException("Malformed native-image condition class name: " + name);
    }
    roots.add(className);
  }

  /* package */
  static void readTypeArray(
      final JsonNode array, final String name, final Set<String> roots, final boolean nullable)
      throws IOException {
    if (array == null && nullable) {
      return;
    }
    if (array == null || !array.isArray()) {
      throw new IOException("Malformed native-image type array: " + name);
    }
    for (final JsonNode type : array) {
      addStandaloneType(type, name, roots);
    }
  }

  /* package */
  static void addStandaloneType(final JsonNode type, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireText(type, "standalone type descriptor", name);
    final String component = NativeImageTypeDescriptor.extractComponentClass(type.textValue());
    if (component == null) {
      throw new IOException("Malformed standalone type descriptor: " + name);
    }
    if (!component.isEmpty()) {
      roots.add(component);
    }
  }

  /* package */
  static void readClassArray(
      final JsonNode array, final String name, final Set<String> roots, final boolean required)
      throws IOException {
    if (array == null && !required) {
      return;
    }
    if (array == null || !array.isArray() || (required && array.isEmpty())) {
      throw new IOException("Malformed native-image class array: " + name);
    }
    for (final JsonNode value : array) {
      addRequiredClass(value, "class name", name, roots);
    }
  }

  /* package */
  static void addRequiredClass(
      final JsonNode node, final String field, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireText(node, field, name);
    final String className = node.textValue();
    if (!NativeImageDynamicRoots.isBinaryClassName(className)) {
      throw new IOException("Malformed " + field + ": " + name);
    }
    roots.add(className);
  }

  /* package */
  static void validateBooleanFields(
      final JsonNode object, final Set<String> fields, final String name) throws IOException {
    for (final String field : fields) {
      if (object.has(field) && !object.get(field).isBoolean()) {
        throw new IOException("Malformed boolean field " + field + " in " + name);
      }
    }
  }

  /* package */
  static void validateStringOrStrings(final JsonNode node, final String name) throws IOException {
    if (node.isTextual()) {
      return;
    }
    if (node.isArray()) {
      for (final JsonNode item : node) {
        if (!item.isTextual()) {
          throw new IOException("Malformed string array item: " + name);
        }
      }
      return;
    }
    throw new IOException("Malformed string metadata value: " + name);
  }
}
