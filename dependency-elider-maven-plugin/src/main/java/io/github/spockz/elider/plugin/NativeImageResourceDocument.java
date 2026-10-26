/* WHY: Validates native-image resource JSON while extracting conditional class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/** Parses supported native-image resource JSON fields. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageResourceDocument {
  /** Shared parser configured for native-image metadata JSON. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private NativeImageResourceDocument() {}

  static void read(final InputStream input, final String name, final Set<String> roots)
      throws IOException {
    final JsonNode document = JSON.readTree(input);
    if (document == null || !document.isObject()) {
      throw new IOException("Malformed native-image resource configuration: " + name);
    }
    validateFields(document, name);
    final JsonNode resources = document.get("resources");
    final JsonNode bundles = document.get("bundles");
    if (resources == null && bundles == null) {
      throw new IOException("Native-image resource configuration is empty: " + name);
    }
    readResources(resources, roots, name);
    readBundles(bundles, roots, name);
    validateGlobalReachability(document, name);
  }

  private static void validateFields(final JsonNode document, final String name)
      throws IOException {
    final java.util.Iterator<String> keys = document.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!Set.of("resources", "bundles", "globallyReachable").contains(key)) {
        throw new IOException("Unsupported native-image resource field " + key + " in " + name);
      }
    }
  }

  private static void readResources(
      final JsonNode resources, final Set<String> roots, final String name) throws IOException {
    if (resources == null) {
      return;
    }
    if (resources.isArray()) {
      NativeImageResourcePatterns.read(resources, roots, name);
    } else if (resources.isObject()) {
      readResourceSections(resources, roots, name);
    } else {
      throw new IOException("Malformed native-image resources section: " + name);
    }
  }

  private static void readResourceSections(
      final JsonNode resources, final Set<String> roots, final String name) throws IOException {
    final java.util.Iterator<String> keys = resources.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!Set.of("includes", "excludes").contains(key)) {
        throw new IOException("Unsupported native-image resources field " + key + " in " + name);
      }
      final JsonNode patterns = resources.get(key);
      if (!patterns.isArray()) {
        throw new IOException("Malformed native-image resource patterns: " + name);
      }
      NativeImageResourcePatterns.read(patterns, roots, name);
    }
  }

  private static void readBundles(
      final JsonNode bundles, final Set<String> roots, final String name) throws IOException {
    if (bundles == null) {
      return;
    }
    if (!bundles.isArray()) {
      throw new IOException("Malformed native-image bundles section: " + name);
    }
    for (final JsonNode bundle : bundles) {
      readBundle(bundle, roots, name);
    }
  }

  private static void readBundle(final JsonNode bundle, final Set<String> roots, final String name)
      throws IOException {
    final JsonNode bundleName = bundle.get("name");
    if (!bundle.isObject()
        || bundleName == null
        || !bundleName.isTextual()
        || !NativeImageDynamicRoots.isBinaryClassName(bundleName.textValue())) {
      throw new IOException("Malformed native-image bundle name: " + name);
    }
    roots.add(bundleName.textValue());
    final JsonNode condition = bundle.get("condition");
    if (condition != null) {
      NativeImageResourcePatterns.readCondition(condition, roots, name);
    }
  }

  private static void validateGlobalReachability(final JsonNode document, final String name)
      throws IOException {
    final JsonNode globallyReachable = document.get("globallyReachable");
    if (globallyReachable != null && !globallyReachable.isBoolean()) {
      throw new IOException("Malformed native-image globallyReachable value: " + name);
    }
  }
}
