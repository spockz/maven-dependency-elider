/* WHY: Dispatches audited native-image descriptors to bounded class-root readers. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
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
    final NativeImageDescriptorKind kind = NativeImageDescriptorKind.classConfigFor(name);
    if (kind == null) {
      throw new IOException("Unsupported native-image class configuration: " + name);
    }
    readNativeImageClassConfig(NativeImageInput.archiveEntry(archive, name, kind), roots);
  }

  /* package */
  static void readNativeImageClassConfig(final NativeImageInput input, final Set<String> roots)
      throws IOException {
    final JsonNode document = readDocument(input.open(), input.name());
    dispatch(document, input, roots);
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
      final JsonNode document, final NativeImageInput input, final Set<String> roots)
      throws IOException {
    NativeImageClassConfigDispatcher.dispatch(document, input, roots);
  }

  static boolean isReflectionConfig(final String name) {
    return name.endsWith("reflect-config.json")
        || name.endsWith("jni-config.json")
        || name.endsWith("-reflection.json")
        || name.endsWith("-jni.json");
  }

  static boolean isNativeImageClassConfig(final String name) {
    return NativeImageDescriptorKind.classConfigFor(name) != null;
  }
}
