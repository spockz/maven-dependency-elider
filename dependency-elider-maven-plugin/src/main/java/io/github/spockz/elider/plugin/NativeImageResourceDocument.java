/* WHY: Validates native-image resource JSON while extracting conditional
 * class roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;

/** Parses supported native-image resource JSON fields. */
final class NativeImageResourceDocument {
  /** Shared parser configured for native-image metadata JSON. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private NativeImageResourceDocument() {}

  /* package */
  static void read(final NativeImageInput input, final Set<String> roots) throws IOException {
    read(input, roots, null);
  }

  /* package */ static void read(
      final NativeImageInput input,
      final Set<String> roots,
      final NativeImagePolicyRoots.ResourcePatterns selections)
      throws IOException {
    final String name = input.name();
    final JsonNode document;
    try (InputStream source = input.open();
        JsonParser parser = JSON.getFactory().createParser(source)) {
      document = JSON.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Trailing data in native-image resource configuration: " + name);
      }
    }
    if (document == null || !document.isObject()) {
      throw new IOException("Malformed native-image resource configuration: " + name);
    }
    validateFields(document, name);
    final JsonNode resources = document.get("resources");
    final JsonNode bundles = document.get("bundles");
    final JsonNode globs = document.get("globs");
    final String identity = input.selectionIdentity();
    readResources(resources, roots, name, selections, identity + ":resources");
    NativeImageResourceBundles.read(bundles, roots, name, selections, identity + ":bundles");
    NativeImageResourcePatterns.readGlobs(globs, roots, name, selections, identity + ":resources");
  }

  private static void validateFields(final JsonNode document, final String name)
      throws IOException {
    final java.util.Iterator<String> keys = document.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!Set.of("resources", "bundles", "globs").contains(key)) {
        throw new IOException("Unsupported native-image resource field " + key + " in " + name);
      }
    }
  }

  private static void readResources(
      final JsonNode resources,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (resources == null) {
      return;
    }
    if (resources.isArray()) {
      NativeImageResourcePatterns.read(resources, roots, name, selections, false, selectionGroup);
    } else if (resources.isObject()) {
      readResourceSections(resources, roots, name, selections, selectionGroup);
    } else {
      throw new IOException("Malformed native-image resources section: " + name);
    }
  }

  private static void readResourceSections(
      final JsonNode resources,
      final Set<String> roots,
      final String name,
      final NativeImagePolicyRoots.ResourcePatterns selections,
      final String selectionGroup)
      throws IOException {
    if (!resources.has("includes")) {
      throw new IOException("Missing native-image resource includes: " + name);
    }
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
      NativeImageResourcePatterns.read(
          patterns, roots, name, selections, "excludes".equals(key), selectionGroup);
    }
  }
}
