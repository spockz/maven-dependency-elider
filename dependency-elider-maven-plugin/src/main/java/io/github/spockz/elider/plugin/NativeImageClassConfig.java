/* WHY: Dispatches audited native-image descriptors to bounded class-root readers. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Validates supported native-image metadata and extracts modeled class references. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageClassConfig {
  /** Rejects duplicate keys before descriptor schema validation. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  private NativeImageClassConfig() {}

  static void readNativeImageClassConfig(
      final JarFile archive, final String name, final Set<String> roots) throws IOException {
    final JarEntry entry = archive.getJarEntry(name);
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Native-image class configuration is missing: " + name);
    }
    final JsonNode document = readDocument(archive.getInputStream(entry), name);
    dispatch(document, name, archive, roots);
  }

  private static JsonNode readDocument(final InputStream input, final String name)
      throws IOException {
    try (InputStream source = input;
        JsonParser parser = JSON.getFactory().createParser(source)) {
      final JsonNode document = JSON.readTree(parser);
      if (parser.nextToken() != null) {
        throw new IOException("Trailing data in native-image configuration: " + name);
      }
      if (document == null) {
        throw new IOException("Malformed native-image configuration: " + name);
      }
      return document;
    }
  }

  private static void dispatch(
      final JsonNode document, final String name, final JarFile archive, final Set<String> roots)
      throws IOException {
    if (dispatchNamed(document, name, archive, roots)) {
      return;
    }
    if (document.isArray()) {
      NativeImageReflectionConfig.read(document, name, roots);
    } else if (name.endsWith("serialization-config.json")) {
      NativeImageSerializationConfig.readDocument(document, name, roots);
    } else {
      throw new IOException("Malformed native-image configuration: " + name);
    }
  }

  private static boolean dispatchNamed(
      final JsonNode document, final String name, final JarFile archive, final Set<String> roots)
      throws IOException {
    return dispatchCoreSchema(document, name, archive, roots)
        || dispatchStandaloneSupplement(document, name, roots);
  }

  private static boolean dispatchCoreSchema(
      final JsonNode document, final String name, final JarFile archive, final Set<String> roots)
      throws IOException {
    if (name.endsWith("reachability-metadata.json")) {
      NativeImageUnifiedConfig.read(document, name, roots);
      return true;
    } else if (name.endsWith("predefined-classes-config.json")) {
      NativeImagePredefinedConfig.read(document, name, archive, roots);
      return true;
    } else if (name.endsWith("serialization-deny-config.json")) {
      NativeImageSerializationDenyConfig.read(document, name);
      return true;
    }
    return false;
  }

  private static boolean dispatchStandaloneSupplement(
      final JsonNode document, final String name, final Set<String> roots) throws IOException {
    if (name.endsWith("object-inlining-config.json")) {
      NativeImageObjectInliningConfig.read(document, name, roots);
    } else if (name.endsWith("foreign-config.json")) {
      NativeImageStandaloneSupplementalConfig.readForeign(document, name);
    } else if (document.isArray() && name.endsWith("serialization-config.json")) {
      for (final JsonNode element : document) {
        NativeImageSerializationConfig.readLegacy(element, name, roots);
      }
    } else {
      return false;
    }
    return true;
  }

  static boolean isReflectionConfig(final String name) {
    return name.endsWith("reflect-config.json")
        || name.endsWith("jni-config.json")
        || name.endsWith("-reflection.json")
        || name.endsWith("-jni.json");
  }

  static boolean isNativeImageClassConfig(final String name) {
    return isReflectionConfig(name)
        || name.endsWith("proxy-config.json")
        || name.endsWith("serialization-config.json")
        || name.endsWith("predefined-classes-config.json")
        || name.endsWith("reachability-metadata.json")
        || name.endsWith("foreign-config.json")
        || name.endsWith("object-inlining-config.json")
        || name.endsWith("serialization-deny-config.json");
  }
}
