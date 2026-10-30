/* WHY: Resolves only object-inlining map keys; selector strings are not type references. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

/** Reads the six audited object-inlining maps. */
final class NativeImageObjectInliningConfig {
  /** Maps whose values are field selectors. */
  private static final Set<String> FIELD_MAPS =
      Set.of("value_fields", "value_graphs", "value_fields_mutable", "value_graphs_mutable");

  /** Maps whose values are scope selectors. */
  private static final Set<String> TYPE_MAPS = Set.of("value_field_types", "value_graph_types");

  private NativeImageObjectInliningConfig() {}

  /* package */
  static void read(final JsonNode document, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireObject(document, "object-inlining configuration", name);
    NativeImageJsonSupport.validateFields(
        document,
        Set.of(
            "value_fields",
            "value_graphs",
            "value_fields_mutable",
            "value_graphs_mutable",
            "value_field_types",
            "value_graph_types"),
        "object-inlining configuration",
        name);
    for (final String section : FIELD_MAPS) {
      readMap(document.get(section), section, name, roots, "field selector");
    }
    for (final String section : TYPE_MAPS) {
      readMap(document.get(section), section, name, roots, "scope selector");
    }
  }

  private static void readMap(
      final JsonNode map,
      final String section,
      final String name,
      final Set<String> roots,
      final String selectorKind)
      throws IOException {
    if (map == null) {
      return;
    }
    NativeImageJsonSupport.requireObject(map, "object-inlining map " + section, name);
    final Iterator<String> keys = map.fieldNames();
    while (keys.hasNext()) {
      final String typeName = keys.next();
      NativeImageRootSupport.addRequiredClass(
          JsonNodeFactory.instance.textNode(typeName), "object-inlining class", name, roots);
      final JsonNode selectors = map.get(typeName);
      if (selectors == null || !selectors.isArray()) {
        throw new IOException("Malformed object-inlining selectors in " + section + ": " + name);
      }
      for (final JsonNode selector : selectors) {
        NativeImageJsonSupport.requireText(selector, selectorKind, name);
      }
    }
  }
}
