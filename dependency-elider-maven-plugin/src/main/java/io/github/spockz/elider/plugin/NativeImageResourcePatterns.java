/* WHY: Validates JDK21 resource patterns and extracts only conditional class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads the selected legacy resource and glob descriptor forms. */
final class NativeImageResourcePatterns {
  private NativeImageResourcePatterns() {}

  /* package */
  static void read(final JsonNode patterns, final Set<String> roots, final String name)
      throws IOException {
    readEntries(patterns, roots, name, "pattern", Set.of("condition"));
  }

  /* package */
  static void readGlobs(final JsonNode globs, final Set<String> roots, final String name)
      throws IOException {
    if (globs == null) {
      return;
    }
    readEntries(globs, roots, name, "glob", Set.of("condition", "module"));
  }

  private static void readEntries(
      final JsonNode entries,
      final Set<String> roots,
      final String name,
      final String valueField,
      final Set<String> optionalFields)
      throws IOException {
    if (!entries.isArray()) {
      throw new IOException("Malformed native-image " + valueField + " entries: " + name);
    }
    final Set<String> supported = new java.util.HashSet<>(optionalFields);
    supported.add(valueField);
    for (final JsonNode entry : entries) {
      readEntry(entry, roots, name, valueField, supported);
    }
  }

  private static void readEntry(
      final JsonNode entry,
      final Set<String> roots,
      final String name,
      final String valueField,
      final Set<String> supported)
      throws IOException {
    if (!entry.isObject()) {
      throw new IOException("Malformed native-image " + valueField + " entry: " + name);
    }
    validateFields(entry, supported, name);
    validateValue(entry.get(valueField), valueField, name);
    validateModule(entry, name);
    readEntryCondition(entry.get("condition"), roots, name);
  }

  private static void validateValue(
      final JsonNode value, final String valueField, final String name) throws IOException {
    if (value == null || !value.isTextual()) {
      throw new IOException("Malformed native-image " + valueField + ": " + name);
    }
  }

  private static void validateModule(final JsonNode entry, final String name) throws IOException {
    if (entry.has("module") && !entry.get("module").isTextual()) {
      throw new IOException("Malformed native-image resource module: " + name);
    }
  }

  private static void readEntryCondition(
      final JsonNode condition, final Set<String> roots, final String name) throws IOException {
    if (condition != null) {
      readCondition(condition, roots, name);
    }
  }

  private static void validateFields(
      final JsonNode entry, final Set<String> supported, final String name) throws IOException {
    final java.util.Iterator<String> fields = entry.fieldNames();
    while (fields.hasNext()) {
      final String field = fields.next();
      if (!supported.contains(field)) {
        throw new IOException(
            "Unsupported native-image resource pattern field " + field + " in " + name);
      }
    }
  }

  /* package */
  static void readCondition(final JsonNode condition, final Set<String> roots, final String name)
      throws IOException {
    if (!condition.isObject() || condition.size() != 1) {
      throw new IOException("Malformed native-image condition: " + name);
    }
    final String conditionType = condition.fieldNames().next();
    if (!isValidConditionType(conditionType)) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    final JsonNode className = condition.get(conditionType);
    final String componentClass = parseConditionClass(className, name);
    roots.add(componentClass);
  }

  private static boolean isValidConditionType(final String type) {
    return "typeReachable".equals(type) || "typeReached".equals(type);
  }

  private static String parseConditionClass(final JsonNode node, final String name)
      throws IOException {
    if (node == null || !node.isTextual()) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    final String componentClass = NativeImageTypeDescriptor.extractComponentClass(node.textValue());
    if (componentClass == null
        || componentClass.isEmpty()
        || !NativeImageDynamicRoots.isBinaryClassName(componentClass)) {
      throw new IOException("Unsupported native-image condition: " + name);
    }
    return componentClass;
  }
}
