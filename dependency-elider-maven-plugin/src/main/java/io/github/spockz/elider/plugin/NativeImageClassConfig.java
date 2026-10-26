/* WHY: Validates native-image class and proxy configuration roots. */

package io.github.spockz.elider.plugin;

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
  private static final ObjectMapper JSON = new ObjectMapper();

  private NativeImageClassConfig() {}

  static void readNativeImageClassConfig(
      final JarFile archive, final String name, final Set<String> roots) throws IOException {
    final JarEntry entry = archive.getJarEntry(name);
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Native-image class configuration is missing: " + name);
    }
    try (InputStream input = archive.getInputStream(entry)) {
      final JsonNode document = JSON.readTree(input);
      if (document == null || !document.isArray()) {
        throw new IOException("Malformed native-image configuration: " + name);
      }
      readElements(document, name, roots);
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
    if (!element.isArray()) {
      throw new IOException("Malformed proxy configuration: " + name);
    }
    for (final JsonNode interfaceName : element) {
      if (!interfaceName.isTextual()
          || !NativeImageDynamicRoots.isBinaryClassName(interfaceName.textValue())) {
        throw new IOException("Malformed proxy interface name: " + name);
      }
      roots.add(interfaceName.textValue());
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
