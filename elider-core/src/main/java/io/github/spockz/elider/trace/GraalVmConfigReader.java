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
@SuppressWarnings("PMD.GodClass")
public final class GraalVmConfigReader implements RuntimeTraceReader {
  /** Parses the JSON tree used by GraalVM configuration files. */
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  /** Primitive types recognized in reflection metadata. */
  private static final Set<String> PRIMITIVE_TYPES =
      Set.of("boolean", "byte", "char", "short", "int", "long", "float", "double", "void");

  /** Primitive type descriptor characters recognized in JVM descriptors. */
  private static final Set<Character> PRIMITIVE_DESCRIPTORS =
      Set.of('Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'V');

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
  @SuppressWarnings("PMD.CyclomaticComplexity")
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported GraalVM reflection configuration file: " + path);
    }
    try (JsonParser parser = OBJECT_MAPPER.createParser(path.toFile())) {
      parser.enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
      final JsonNode root = OBJECT_MAPPER.readTree(parser);
      if (root == null || (!root.isArray() && !root.isObject())) {
        throw new IOException(
            "GraalVM reflection configuration must contain a JSON array or object: " + path);
      }
      if (parser.nextToken() != null) {
        throw new IOException(
            "GraalVM reflection configuration has trailing JSON content: " + path);
      }
      if (root.isArray()) {
        return TraceData.of(readClassNames(root, path));
      }
      return TraceData.of(readUnifiedClassNames(root, path));
    }
  }

  private static Set<String> readUnifiedClassNames(final JsonNode root, final Path path)
      throws IOException {
    final Set<String> classes = new HashSet<>();
    readUnifiedSection(root.get("reflection"), classes, path);
    readUnifiedSection(root.get("jni"), classes, path);
    readUnifiedSection(root.get("serialization"), classes, path);
    return classes;
  }

  private static void readUnifiedSection(
      final JsonNode section, final Set<String> classes, final Path path) throws IOException {
    if (section == null) {
      return;
    }
    if (!section.isArray()) {
      throw new IOException("Malformed GraalVM reachability metadata section in " + path);
    }
    for (final JsonNode descriptor : section) {
      final String className = readClassName(descriptor, path);
      if (className != null) {
        classes.add(className);
      }
    }
  }

  private static Set<String> readClassNames(final JsonNode root, final Path path)
      throws IOException {
    final Set<String> classes = new HashSet<>();
    for (final JsonNode descriptor : root) {
      final String className = readClassName(descriptor, path);
      if (className != null) {
        classes.add(className);
      }
    }
    return classes;
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private static String readClassName(final JsonNode descriptor, final Path path)
      throws IOException {
    if (!descriptor.isObject()) {
      throw new IOException("Malformed GraalVM reflection class descriptor in " + path);
    }
    final JsonNode name =
        descriptor.hasNonNull("name") ? descriptor.get("name") : descriptor.get("type");
    if (name == null || !name.isTextual()) {
      throw new IOException("GraalVM reflection class descriptor has no valid name in " + path);
    }
    final String componentClass = extractComponentClass(name.asText());
    if (componentClass == null) {
      throw new IOException("GraalVM reflection class descriptor has no valid name in " + path);
    }
    return componentClass.isEmpty() ? null : componentClass;
  }

  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.AvoidDeeplyNestedIfStmts"
  })
  private static String extractComponentClass(final String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    final String trimmed = value.trim();

    if (trimmed.startsWith("[")) {
      int index = 0;
      while (index < trimmed.length() && trimmed.charAt(index) == '[') {
        index++;
      }
      final String element = trimmed.substring(index);
      if (element.startsWith("L") && element.endsWith(";") && element.length() > 2) {
        final String className = element.substring(1, element.length() - 1).replace('/', '.');
        if (isBinaryClassName(className)) {
          return className;
        }
      } else if (element.length() == 1 && PRIMITIVE_DESCRIPTORS.contains(element.charAt(0))) {
        return "";
      }
      return null;
    }

    if (trimmed.endsWith("[]")) {
      String elementType = trimmed;
      while (elementType.endsWith("[]")) {
        elementType = elementType.substring(0, elementType.length() - 2).trim();
      }
      if (PRIMITIVE_TYPES.contains(elementType)) {
        return "";
      }
      if (isBinaryClassName(elementType)) {
        return elementType;
      }
      return null;
    }

    if (PRIMITIVE_TYPES.contains(trimmed)) {
      return "";
    }

    if (isBinaryClassName(trimmed)) {
      return trimmed;
    }

    return null;
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
