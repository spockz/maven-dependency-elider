/* WHY: Validates JDK21 resource patterns and extracts only conditional class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads the selected legacy resource and glob descriptor forms. */
final class NativeImageResourcePatterns {
  /** WHY: The parser distinguishes legacy regex entries from glob extensions. */
  private static final String GLOB_FIELD = "glob";

  /** WHY: Module selectors are the only optional field on glob entries. */
  private static final String MODULE_FIELD = "module";

  /** WHY: Legacy resource patterns use a separate descriptor field name. */
  private static final String PATTERN_FIELD = "pattern";

  private NativeImageResourcePatterns() {}

  /* package */ static void read(
      final JsonNode patterns,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final boolean excluded,
      final String selectionGroup)
      throws IOException {
    readEntries(
        patterns,
        roots,
        name,
        PATTERN_FIELD,
        Set.of("condition"),
        selections,
        excluded,
        selectionGroup);
  }

  /* package */ static void readGlobs(
      final JsonNode globs,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (globs == null) {
      return;
    }
    readEntries(
        globs,
        roots,
        name,
        GLOB_FIELD,
        Set.of("condition", MODULE_FIELD),
        selections,
        false,
        selectionGroup);
  }

  private static void readEntries(
      final JsonNode entries,
      final Set<String> roots,
      final String name,
      final String valueField,
      final Set<String> optionalFields,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final boolean excluded,
      final String selectionGroup)
      throws IOException {
    if (!entries.isArray()) {
      throw new IOException("Malformed native-image " + valueField + " entries: " + name);
    }
    final Set<String> supported = new java.util.HashSet<>(optionalFields);
    supported.add(valueField);
    for (final JsonNode entry : entries) {
      readEntry(entry, roots, name, valueField, supported, selections, excluded, selectionGroup);
    }
  }

  private static void readEntry(
      final JsonNode entry,
      final Set<String> roots,
      final String name,
      final String valueField,
      final Set<String> supported,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final boolean excluded,
      final String selectionGroup)
      throws IOException {
    if (!entry.isObject()) {
      throw new IOException("Malformed native-image " + valueField + " entry: " + name);
    }
    validateFields(entry, supported, name);
    final String expression = validateValue(entry.get(valueField), valueField, name);
    validateModule(entry, name);
    if (selections != null) {
      final String module = entry.has(MODULE_FIELD) ? entry.get(MODULE_FIELD).textValue() : null;
      selections.addDescriptorSelector(valueField, expression, module, excluded, selectionGroup);
    }
    final JsonNode condition = entry.get("condition");
    if (condition != null) {
      NativeImageResourceCondition.read(condition, roots, name);
    }
  }

  private static String validateValue(
      final JsonNode value, final String valueField, final String name) throws IOException {
    if (value == null || !value.isTextual() || value.textValue().isEmpty()) {
      throw new IOException("Malformed native-image " + valueField + ": " + name);
    }
    return value.textValue();
  }

  private static void validateModule(final JsonNode entry, final String name) throws IOException {
    if (entry.has(MODULE_FIELD) && !entry.get(MODULE_FIELD).isTextual()) {
      throw new IOException("Malformed native-image resource module: " + name);
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
}
