/* WHY: Isolates strict trim-manifest parsing so malformed cache bytes cannot be reused. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;

/** Reads trim-cache manifests without JSON duplicate, token, or scalar coercion. */
final class TrimCacheManifestReader {
  /** Rejects duplicate keys, unknown properties, trailing documents, and coercions. */
  private static final ObjectMapper JSON =
      new ObjectMapper()
          .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
          .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS);

  private TrimCacheManifestReader() {
    throw new AssertionError("No instances");
  }

  /** Reads a valid cache manifest or returns null. */
  /* package */
  static JarTrimCache.CacheManifest read(final Path path) {
    try {
      final JsonNode root = JSON.readValue(path.toFile(), JsonNode.class);
      return validManifestShape(root)
          ? JSON.treeToValue(root, JarTrimCache.CacheManifest.class)
          : null;
    } catch (final IOException exception) {
      return null;
    }
  }

  private static boolean validManifestShape(final JsonNode root) {
    return root != null
        && root.isObject()
        && root.path("schemaVersion").isIntegralNumber()
        && root.path("schemaVersion").canConvertToInt()
        && root.path("formatId").isTextual()
        && validProducerShape(root.path("producer"))
        && root.path("fingerprint").isTextual()
        && root.path("entries").isArray();
  }

  private static boolean validProducerShape(final JsonNode producer) {
    return producer.isObject()
        && producer.path("groupId").isTextual()
        && producer.path("artifactId").isTextual()
        && producer.path("version").isTextual()
        && (producer.path("buildIdentity").isTextual() || producer.path("buildIdentity").isNull());
  }
}
