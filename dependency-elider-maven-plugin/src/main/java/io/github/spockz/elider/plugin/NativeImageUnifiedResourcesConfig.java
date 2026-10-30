/* WHY: Parses classpath resource entries in unified metadata 1.2.0. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads unified resource and bundle descriptors. */
final class NativeImageUnifiedResourcesConfig {
  /** WHY: Resource entries choose between a glob and this bundle class name field. */
  private static final String BUNDLE = "bundle";

  private NativeImageUnifiedResourcesConfig() {}

  /* package */
  static void readUnifiedResources(
      final JsonNode resources, final String name, final Set<String> roots) throws IOException {
    if (resources == null) {
      return;
    }
    if (!resources.isArray()) {
      throw new IOException("Malformed reachability resources section: " + name);
    }
    for (final JsonNode item : resources) {
      readResource(item, name, roots);
    }
  }

  private static void readResource(final JsonNode item, final String name, final Set<String> roots)
      throws IOException {
    NativeImageJsonSupport.requireObject(item, "resource entry", name);
    NativeImageJsonSupport.validateFields(
        item, Set.of("reason", "condition", "module", "glob", BUNDLE), "resource entry", name);
    final boolean glob = item.has("glob");
    final boolean bundle = item.has(BUNDLE);
    if (glob == bundle) {
      throw new IOException("Malformed reachability resource entry: " + name);
    }
    NativeImageJsonSupport.requireText(item.get(glob ? "glob" : BUNDLE), "resource name", name);
    readOptionalModule(item, name);
    readReason(item, name);
    NativeImageRootSupport.readCondition(item.get("condition"), name, roots, true);
    if (bundle) {
      addBundleRoot(item.get(BUNDLE).textValue(), name, roots);
    }
  }

  private static void readOptionalModule(final JsonNode item, final String name)
      throws IOException {
    if (item.has("module")) {
      NativeImageJsonSupport.requireText(item.get("module"), "resource module", name);
    }
  }

  private static void readReason(final JsonNode item, final String name) throws IOException {
    if (item.has("reason")) {
      NativeImageRootSupport.validateStringOrStrings(item.get("reason"), name);
    }
  }

  private static void addBundleRoot(
      final String bundleName, final String name, final Set<String> roots) throws IOException {
    final String component = NativeImageTypeDescriptor.extractComponentClass(bundleName);
    if (component == null || component.isEmpty()) {
      throw new IOException("Malformed resource bundle class name: " + name);
    }
    roots.add(component);
  }
}
