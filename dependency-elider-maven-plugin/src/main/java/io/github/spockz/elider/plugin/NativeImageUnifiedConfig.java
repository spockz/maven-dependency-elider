/* WHY: Dispatches the audited 1.2.0 reachability sections to schema-specific readers. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Validates the unified reachability metadata envelope. */
final class NativeImageUnifiedConfig {
  private NativeImageUnifiedConfig() {}

  /* package */
  static void read(final JsonNode document, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireObject(document, "reachability metadata", name);
    NativeImageJsonSupport.validateFields(
        document,
        Set.of("comment", "reflection", "resources", "foreign"),
        "reachability metadata",
        name);
    if (document.has("comment")) {
      NativeImageRootSupport.validateStringOrStrings(document.get("comment"), name);
    }
    NativeImageUnifiedReflectionConfig.readUnifiedReflection(
        document.get("reflection"), name, roots);
    NativeImageUnifiedResourcesConfig.readUnifiedResources(document.get("resources"), name, roots);
    NativeImageUnifiedForeignConfig.readUnifiedForeign(document.get("foreign"), name, roots);
  }
}
