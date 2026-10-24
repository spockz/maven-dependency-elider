/* WHY: Converts GraalVM reflection configuration into observations for the common trace model. */

package io.github.spockz.elider.trace;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Reads GraalVM {@code reflect-config.json} class descriptors. */
public final class GraalVmConfigReader implements RuntimeTraceReader {
  /** Parses the JSON tree used by GraalVM configuration files. */
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /** Creates a reader for GraalVM reflection configuration files. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public GraalVmConfigReader() {}

  /** Recognizes JSON configuration paths. */
  @Override
  public boolean supports(final Path path) {
    final String fileName = supportedFileName(path);
    return fileName != null && fileName.endsWith(".json");
  }

  /** Reads class descriptor names from a reflection configuration array. */
  @Override
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported GraalVM reflection configuration file: " + path);
    }
    try (JsonParser parser = OBJECT_MAPPER.createParser(path.toFile())) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      final JsonNode root = OBJECT_MAPPER.readTree(parser);
      if (root == null || !root.isArray()) {
        throw new IOException(
            "GraalVM reflection configuration must contain a JSON array: " + path);
      }
      if (parser.nextToken() != null) {
        throw new IOException(
            "GraalVM reflection configuration has trailing JSON content: " + path);
      }
      return TraceData.of(readClassNames(root, path));
    }
  }

  private static Set<String> readClassNames(final JsonNode root, final Path path)
      throws IOException {
    final Set<String> classes = new HashSet<>();
    for (final JsonNode descriptor : root) {
      classes.add(readClassName(descriptor, path));
    }
    return classes;
  }

  private static String readClassName(final JsonNode descriptor, final Path path)
      throws IOException {
    if (!descriptor.isObject()) {
      throw new IOException("Malformed GraalVM reflection class descriptor in " + path);
    }
    final JsonNode name = descriptor.get("name");
    if (name == null || !name.isTextual() || !isBinaryClassName(name.asText())) {
      throw new IOException("GraalVM reflection class descriptor has no valid name in " + path);
    }
    return name.asText();
  }

  private static boolean isBinaryClassName(final String name) {
    return name.indexOf('/') < 0 && !TraceClassName.isHidden(name) && TraceClassName.isValid(name);
  }

  private static String supportedFileName(final Path path) {
    if (path == null) {
      return null;
    }
    final Path fileName = path.getFileName();
    if (fileName == null) {
      return null;
    }
    return fileName.toString().toLowerCase(Locale.ROOT);
  }
}
