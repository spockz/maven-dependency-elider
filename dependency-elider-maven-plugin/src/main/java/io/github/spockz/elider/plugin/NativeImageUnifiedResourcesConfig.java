/* WHY: Parses classpath resource entries in unified metadata 1.2.0. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Reads unified resource and bundle descriptors. */
final class NativeImageUnifiedResourcesConfig {
  /** WHY: Resource entries choose between a glob and this bundle class name field. */
  private static final String BUNDLE = "bundle";

  /** WHY: Unified resource entries may select resource glob patterns. */
  private static final String GLOB = "glob";

  /** WHY: Module selectors distinguish classpath and named module scope. */
  private static final String MODULE = "module";

  /** WHY: Reason annotations are validated without adding reachability roots. */
  private static final String REASON = "reason";

  /** WHY: Conditions are retained as roots while resource selection is conservative. */
  private static final String CONDITION = "condition";

  private NativeImageUnifiedResourcesConfig() {}

  /* package */
  static boolean readUnifiedResources(
      final JsonNode resources, final String name, final Set<String> roots) throws IOException {
    return readUnifiedResources(resources, name, roots, null);
  }

  /* package */ static boolean readUnifiedResources(
      final JsonNode resources,
      final String name,
      final Set<String> roots,
      final NativeImagePolicyRoots.ResourcePatterns selections)
      throws IOException {
    return readUnifiedResources(resources, name, roots, selections, name);
  }

  /* package */ static boolean readUnifiedResources(
      final JsonNode resources,
      final String name,
      final Set<String> roots,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (resources == null) {
      return false;
    }
    if (!resources.isArray()) {
      throw new IOException("Malformed reachability resources section: " + name);
    }
    for (final JsonNode item : resources) {
      readResource(item, name, roots, selections, selectionGroup);
    }
    return !resources.isEmpty();
  }

  private static void readResource(
      final JsonNode item,
      final String name,
      final Set<String> roots,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    NativeImageJsonSupport.requireObject(item, "resource entry", name);
    NativeImageJsonSupport.validateFields(
        item, Set.of(REASON, CONDITION, MODULE, GLOB, BUNDLE), "resource entry", name);
    final boolean glob = item.has(GLOB);
    final boolean bundle = item.has(BUNDLE);
    if (glob == bundle) {
      throw new IOException("Malformed reachability resource entry: " + name);
    }
    NativeImageJsonSupport.requireText(item.get(glob ? GLOB : BUNDLE), "resource name", name);
    readOptionalModule(item, name);
    readReason(item, name);
    NativeImageRootSupport.readCondition(item.get(CONDITION), name, roots, true);
    if (bundle) {
      final String bundleClass = bundleClass(item.get(BUNDLE).textValue(), name);
      if (selections == null) {
        roots.add(bundleClass);
      } else {
        selections.includeBundle(bundleClass, optionalModule(item), selectionGroup);
      }
    } else if (selections != null) {
      selections.includeGlob(item.get(GLOB).textValue(), optionalModule(item), selectionGroup);
    }
  }

  private static String optionalModule(final JsonNode item) {
    return item.has(MODULE) ? item.get(MODULE).textValue() : null;
  }

  private static void readOptionalModule(final JsonNode item, final String name)
      throws IOException {
    if (item.has(MODULE)) {
      NativeImageJsonSupport.requireText(item.get("module"), "resource module", name);
    }
  }

  private static void readReason(final JsonNode item, final String name) throws IOException {
    if (item.has(REASON)) {
      NativeImageRootSupport.validateStringOrStrings(item.get(REASON), name);
    }
  }

  private static String bundleClass(final String bundleName, final String name) throws IOException {
    final String component = NativeImageTypeDescriptor.extractComponentClass(bundleName);
    if (component == null
        || component.isEmpty()
        || !NativeImageDynamicRoots.isBinaryClassName(component)) {
      throw new IOException("Malformed resource bundle class name: " + name);
    }
    return component;
  }
}
