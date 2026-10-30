/* WHY: Keeps bundle class names and conditions in the resource root model. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

/** Reads the resource-config bundle descriptor form. */
final class NativeImageResourceBundles {
  private NativeImageResourceBundles() {}

  /* package */
  static void read(final JsonNode bundles, final Set<String> roots, final String name)
      throws IOException {
    read(bundles, roots, name, null);
  }

  /* package */ static void read(
      final JsonNode bundles,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections)
      throws IOException {
    read(bundles, roots, name, selections, name);
  }

  /* package */ static void read(
      final JsonNode bundles,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (bundles == null) {
      return;
    }
    if (!bundles.isArray()) {
      throw new IOException("Malformed native-image bundles section: " + name);
    }
    for (final JsonNode bundle : bundles) {
      readBundle(bundle, roots, name, selections, selectionGroup);
    }
  }

  private static void readBundle(
      final JsonNode bundle,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (!bundle.isObject()) {
      throw new IOException("Malformed native-image bundle name: " + name);
    }
    validateFields(bundle, name);
    addBundleName(bundle.get("name"), roots, name, selections, selectionGroup);
    validateLocales(bundle.get("locales"), name);
    addBundleClasses(bundle.get("classNames"), roots, name);
    final JsonNode condition = bundle.get("condition");
    if (condition != null) {
      NativeImageResourceCondition.read(condition, roots, name);
    }
  }

  private static void validateLocales(final JsonNode locales, final String name)
      throws IOException {
    if (locales == null) {
      return;
    }
    if (!locales.isArray()) {
      throw new IOException("Malformed native-image bundle locales: " + name);
    }
    for (final JsonNode locale : locales) {
      if (!locale.isTextual()) {
        throw new IOException("Malformed native-image bundle locale: " + name);
      }
    }
  }

  private static void addBundleName(
      final JsonNode bundleName,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (bundleName == null
        || !bundleName.isTextual()
        || !NativeImageBundleResourceSupport.isBundleName(bundleName.textValue())) {
      throw new IOException("Malformed native-image bundle name: " + name);
    }
    if (selections == null) {
      if (NativeImageDynamicRoots.isBinaryClassName(bundleName.textValue())) {
        roots.add(bundleName.textValue());
      }
    } else {
      selections.includeBundle(bundleName.textValue(), null, selectionGroup);
    }
  }

  private static void addBundleClasses(
      final JsonNode classNames, final Set<String> roots, final String name) throws IOException {
    if (classNames == null) {
      return;
    }
    if (!classNames.isArray()) {
      throw new IOException("Malformed native-image bundle classNames: " + name);
    }
    for (final JsonNode className : classNames) {
      if (!className.isTextual()
          || !NativeImageDynamicRoots.isBinaryClassName(className.textValue())) {
        throw new IOException("Malformed native-image bundle class name: " + name);
      }
      roots.add(className.textValue());
    }
  }

  private static void validateFields(final JsonNode bundle, final String name) throws IOException {
    final Iterator<String> keys = bundle.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!Set.of("name", "classNames", "condition", "locales").contains(key)) {
        throw new IOException("Unsupported native-image bundle field " + key + " in " + name);
      }
    }
  }
}
