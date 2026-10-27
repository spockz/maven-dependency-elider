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
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageClassConfig {
  /** Shared parser configured for native-image metadata JSON. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);

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
        if (document == null || !document.isArray()) {
          throw new IOException("Malformed native-image configuration: " + name);
        }
        readElements(document, name, roots);
      }
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
    final JsonNode className = element.get("name");
    if (className == null
        || !className.isTextual()
        || !NativeImageDynamicRoots.isBinaryClassName(className.textValue())) {
      throw new IOException("Reflect configuration lacks a valid class name: " + name);
    }
    roots.add(className.textValue());
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

  private static void readProxyCondition(
      final JsonNode condition, final String name, final Set<String> roots) throws IOException {
    if (condition != null) {
      if (!condition.isObject()) {
        throw new IOException("Malformed proxy condition: " + name);
      }
      validateFields(condition, Set.of("typeReachable"), "proxy condition", name);
      final JsonNode conditionClass = condition.get("typeReachable");
      if (conditionClass == null
          || !conditionClass.isTextual()
          || !NativeImageDynamicRoots.isBinaryClassName(conditionClass.textValue())) {
        throw new IOException("Malformed proxy condition class name: " + name);
      }
      roots.add(conditionClass.textValue());
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

  static boolean isNativeImageClassConfig(final String name) {
    return isReflectionConfig(name) || name.endsWith("proxy-config.json");
  }
}
