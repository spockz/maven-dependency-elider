/* WHY: Validates native-image class and proxy configuration roots. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Validates supported native-image metadata. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity"
})
final class NativeImageClassConfig {
  /** Shared parser configured for native-image metadata JSON. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

  /** Primitive type names recognized in reflection metadata. */
  private static final Set<String> PRIMITIVE_TYPES =
      Set.of("boolean", "byte", "char", "short", "int", "long", "float", "double", "void");

  /** Primitive type descriptor characters recognized in JVM descriptors. */
  private static final Set<Character> PRIMITIVE_DESCRIPTORS =
      Set.of('Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'V');

  private NativeImageClassConfig() {}

  static void readNativeImageClassConfig(
      final JarFile archive, final String name, final Set<String> roots) throws IOException {
    final JarEntry entry = archive.getJarEntry(name);
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Native-image class configuration is missing: " + name);
    }
    try (InputStream input = archive.getInputStream(entry)) {
      try (JsonParser parser = JSON.getFactory().createParser(input)) {
        final JsonNode document = JSON.readTree(parser);
        if (parser.nextToken() != null) {
          throw new IOException("Trailing data in native-image configuration: " + name);
        }
        if (document == null) {
          throw new IOException("Malformed native-image configuration: " + name);
        }
        if (document.isArray()) {
          readElements(document, name, roots);
        } else if (document.isObject() && isUnifiedReachabilityMetadata(name)) {
          readUnifiedDocument(document, name, roots);
        } else {
          throw new IOException("Malformed native-image configuration: " + name);
        }
      }
    }
  }

  private static void readUnifiedDocument(
      final JsonNode document, final String name, final Set<String> roots) throws IOException {
    readUnifiedSection(document.get("reflection"), name, roots);
    readUnifiedSection(document.get("jni"), name, roots);
    readUnifiedSection(document.get("serialization"), name, roots);
  }

  private static void readUnifiedSection(
      final JsonNode section, final String name, final Set<String> roots) throws IOException {
    if (section == null) {
      return;
    }
    if (!section.isArray()) {
      throw new IOException("Malformed reachability metadata section in " + name);
    }
    for (final JsonNode element : section) {
      readReflectionElement(element, name, roots);
    }
  }

  private static void readElements(
      final JsonNode document, final String name, final Set<String> roots) throws IOException {
    for (final JsonNode element : document) {
      if (isReflectionConfig(name)) {
        readReflectionElement(element, name, roots);
      } else {
        readProxyElement(element, name, roots);
      }
    }
  }

  private static void readReflectionElement(
      final JsonNode element, final String name, final Set<String> roots) throws IOException {
    final JsonNode className =
        element.hasNonNull("name") ? element.get("name") : element.get("type");
    if (className == null || !className.isTextual()) {
      throw new IOException("Reflect configuration lacks a valid class name: " + name);
    }
    final String componentClass = extractComponentClass(className.textValue());
    if (componentClass == null) {
      throw new IOException("Reflect configuration lacks a valid class name: " + name);
    }
    if (!componentClass.isEmpty()) {
      roots.add(componentClass);
    }
    final JsonNode condition = element.get("condition");
    if (condition != null) {
      readReflectionCondition(condition, name, roots);
    }
  }

  private static void readReflectionCondition(
      final JsonNode condition, final String name, final Set<String> roots) throws IOException {
    if (!condition.isObject()) {
      throw new IOException("Malformed reflect condition: " + name);
    }
    final JsonNode conditionClass = condition.get("typeReachable");
    if (conditionClass != null) {
      if (!conditionClass.isTextual()) {
        throw new IOException("Malformed reflect condition class name: " + name);
      }
      final String conditionRoot = extractComponentClass(conditionClass.textValue());
      if (conditionRoot == null) {
        throw new IOException("Malformed reflect condition class name: " + name);
      }
      if (!conditionRoot.isEmpty()) {
        roots.add(conditionRoot);
      }
    }
  }

  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.AvoidDeeplyNestedIfStmts"
  })
  static String extractComponentClass(final String value) {
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
        if (NativeImageDynamicRoots.isBinaryClassName(className)) {
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
      if (NativeImageDynamicRoots.isBinaryClassName(elementType)) {
        return elementType;
      }
      return null;
    }

    if (PRIMITIVE_TYPES.contains(trimmed)) {
      return "";
    }

    if (NativeImageDynamicRoots.isBinaryClassName(trimmed)) {
      return trimmed;
    }

    return null;
  }

  private static void readProxyElement(
      final JsonNode element, final String name, final Set<String> roots) throws IOException {
    if (element.isArray()) {
      readProxyInterfaces(element, name, roots);
      return;
    }
    if (!element.isObject()) {
      throw new IOException("Malformed proxy configuration: " + name);
    }
    validateFields(element, Set.of("condition", "interfaces"), "proxy", name);
    readProxyCondition(element.get("condition"), name, roots);
    readProxyObjectInterfaces(element.get("interfaces"), name, roots);
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private static void readProxyCondition(
      final JsonNode condition, final String name, final Set<String> roots) throws IOException {
    if (condition != null) {
      if (!condition.isObject()) {
        throw new IOException("Malformed proxy condition: " + name);
      }
      validateFields(condition, Set.of("typeReachable"), "proxy condition", name);
      final JsonNode conditionClass = condition.get("typeReachable");
      if (conditionClass == null || !conditionClass.isTextual()) {
        throw new IOException("Malformed proxy condition class name: " + name);
      }
      final String conditionRoot = extractComponentClass(conditionClass.textValue());
      if (conditionRoot == null || conditionRoot.isEmpty()) {
        throw new IOException("Malformed proxy condition class name: " + name);
      }
      roots.add(conditionRoot);
    }
  }

  private static void readProxyObjectInterfaces(
      final JsonNode interfaces, final String name, final Set<String> roots) throws IOException {
    if (interfaces == null || !interfaces.isArray()) {
      throw new IOException("Malformed proxy interfaces: " + name);
    }
    readProxyInterfaces(interfaces, name, roots);
  }

  private static void readProxyInterfaces(
      final JsonNode interfaces, final String name, final Set<String> roots) throws IOException {
    for (final JsonNode interfaceName : interfaces) {
      if (!interfaceName.isTextual()
          || !NativeImageDynamicRoots.isBinaryClassName(interfaceName.textValue())) {
        throw new IOException("Malformed proxy interface name: " + name);
      }
      roots.add(interfaceName.textValue());
    }
  }

  private static void validateFields(
      final JsonNode object, final Set<String> supported, final String section, final String name)
      throws IOException {
    final java.util.Iterator<String> keys = object.fieldNames();
    while (keys.hasNext()) {
      final String key = keys.next();
      if (!supported.contains(key)) {
        throw new IOException(
            "Unsupported native-image " + section + " field " + key + " in " + name);
      }
    }
  }

  private static boolean isReflectionConfig(final String name) {
    return name.endsWith("reflect-config.json")
        || name.endsWith("-reflection.json")
        || name.endsWith("-jni.json");
  }

  private static boolean isUnifiedReachabilityMetadata(final String name) {
    return name.endsWith("reachability-metadata.json");
  }

  static boolean isNativeImageClassConfig(final String name) {
    return isReflectionConfig(name)
        || name.endsWith("proxy-config.json")
        || isUnifiedReachabilityMetadata(name);
  }
}
