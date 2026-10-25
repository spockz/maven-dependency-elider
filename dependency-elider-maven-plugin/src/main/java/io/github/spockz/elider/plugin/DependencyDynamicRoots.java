/* WHY: Finds class names declared by dependency-local dynamic loading metadata before a JAR is
 * trimmed, since ordinary bytecode references cannot describe SPI or native-image lookups. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads dependency-local service provider and supported Graal native-image roots. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.UseExplicitTypes",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AssignmentInOperand",
  "PMD.AvoidDeeplyNestedIfStmts",
  "PMD.GodClass",
  "PMD.NcssCount"
})
final class DependencyDynamicRoots {
  private static final String SERVICES = "META-INF/services/";
  private static final String NATIVE_IMAGE = "META-INF/native-image/";
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String SPRING_FACTORIES = "META-INF/spring.factories";
  private static final String SPRING_IMPORTS =
      "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports";
  private static final String SPRING_METADATA = "META-INF/spring-autoconfigure-metadata.properties";

  record RootScan(Set<String> roots, boolean declaresClassRoots) {
    RootScan {
      roots = Set.copyOf(roots);
    }
  }

  private DependencyDynamicRoots() {}

  static RootScan scan(final java.nio.file.Path jar) throws IOException {
    final Set<String> roots = new LinkedHashSet<>();
    boolean declaresClassRoots = false;
    try (JarFile archive = new JarFile(jar.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory()) {
          continue;
        }
        final String name = entry.getName();
        if (name.startsWith(SERVICES)) {
          declaresClassRoots = true;
          final String service = name.substring(SERVICES.length());
          if (service.isBlank() || service.contains("/")) {
            throw new IOException("Unsupported service descriptor path: " + name);
          }
          roots.add(service);
          try (BufferedReader reader =
              new BufferedReader(
                  new InputStreamReader(archive.getInputStream(entry), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
              final String provider = line.split("#", 2)[0].trim();
              if (!provider.isEmpty()) {
                if (!provider.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*")) {
                  throw new IOException("Malformed service provider in " + name + ": " + provider);
                }
                roots.add(provider);
              }
            }
          }
        } else if (name.startsWith(NATIVE_IMAGE)
            && (name.endsWith("reflect-config.json") || name.endsWith("proxy-config.json"))) {
          declaresClassRoots = true;
          final JsonNode document;
          try (var input = archive.getInputStream(entry)) {
            document = JSON.readTree(input);
          }
          if (!document.isArray()) {
            throw new IOException("Malformed native-image configuration: " + name);
          }
          for (final JsonNode element : document) {
            if (name.endsWith("reflect-config.json")) {
              final JsonNode className = element.get("name");
              if (className == null || !className.isTextual()) {
                throw new IOException("Reflect configuration lacks a class name: " + name);
              }
              roots.add(className.textValue());
            } else {
              if (!element.isArray()) {
                throw new IOException("Malformed proxy configuration: " + name);
              }
              for (final JsonNode interfaceName : element) {
                if (!interfaceName.isTextual()) {
                  throw new IOException("Malformed proxy interface name: " + name);
                }
                roots.add(interfaceName.textValue());
              }
            }
          }
        } else if (name.startsWith(NATIVE_IMAGE)
            && (name.endsWith(".properties")
                || (name.endsWith(".json") && !name.endsWith("resource-config.json")))) {
          throw new IOException("Unsupported native-image class metadata: " + name);
        } else if (SPRING_FACTORIES.equals(name)) {
          declaresClassRoots |= readSpringFactories(archive.getInputStream(entry), roots);
        } else if (SPRING_IMPORTS.equals(name)) {
          declaresClassRoots = true;
          readSpringImports(archive.getInputStream(entry), roots, name);
        } else if (SPRING_METADATA.equals(name)) {
          declaresClassRoots = true;
          readSpringMetadata(archive.getInputStream(entry), roots);
        }
      }
    }
    return new RootScan(roots, declaresClassRoots);
  }

  private static boolean readSpringFactories(final InputStream input, final Set<String> roots)
      throws IOException {
    final Properties factories = new Properties();
    try (InputStream stream = input) {
      factories.load(stream);
    }
    for (final String key : factories.stringPropertyNames()) {
      final String factory = key.trim();
      if (!isBinaryClassName(factory)) {
        throw new IOException("Malformed Spring factory interface name: " + key);
      }
      roots.add(factory);
      for (final String provider : factories.getProperty(key).split(",")) {
        final String className = provider.trim();
        if (!isBinaryClassName(className)) {
          throw new IOException("Malformed Spring factory implementation: " + provider);
        }
        roots.add(className);
      }
    }
    return true;
  }

  private static void readSpringImports(
      final InputStream input, final Set<String> roots, final String entryName) throws IOException {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        final String className = line.split("#", 2)[0].trim();
        if (!className.isEmpty()) {
          if (!isBinaryClassName(className)) {
            throw new IOException("Malformed Spring AutoConfiguration import in " + entryName);
          }
          roots.add(className);
        }
      }
    }
  }

  private static void readSpringMetadata(final InputStream input, final Set<String> roots)
      throws IOException {
    final Properties metadata = new Properties();
    try (InputStream stream = input) {
      metadata.load(stream);
    }
    for (final String propertyKey : metadata.stringPropertyNames()) {
      final String marker = metadataMarker(propertyKey);
      if (marker == null) {
        throw new IOException("Unsupported Spring autoconfigure metadata key: " + propertyKey);
      }
      final int conditionStart = propertyKey.indexOf(marker);
      roots.add(propertyKey.substring(0, conditionStart));
      final String value = metadata.getProperty(propertyKey);
      if (marker.endsWith("Before") || marker.endsWith("After")) {
        for (final String candidate : value.split("[,;\\s]+")) {
          if (!isBinaryClassName(candidate)) {
            throw new IOException("Unsupported Spring autoconfigure metadata value: " + candidate);
          }
          roots.add(candidate);
        }
      } else if (marker.endsWith("Order")) {
        try {
          Integer.parseInt(value);
        } catch (final NumberFormatException exception) {
          throw new IOException(
              "Unsupported Spring autoconfigure order value: " + value, exception);
        }
      } else if (marker.endsWith("Conditional")
          && classValuedCondition(propertyKey.substring(conditionStart + marker.length()))) {
        for (final String candidate : value.split("[,;\\s]+")) {
          if (!isBinaryClassName(candidate)) {
            throw new IOException("Unsupported Spring autoconfigure class value: " + candidate);
          }
          roots.add(candidate);
        }
      }
    }
  }

  private static boolean classValuedCondition(final String condition) {
    return condition.startsWith("OnClass")
        || condition.startsWith("OnMissingClass")
        || condition.startsWith("OnBean")
        || condition.startsWith("OnMissingBean")
        || condition.startsWith("OnSingleCandidate");
  }

  private static String metadataMarker(final String key) {
    for (final String marker :
        Set.of(
            ".Conditional", ".AutoConfigureBefore", ".AutoConfigureAfter", ".AutoConfigureOrder")) {
      if (key.contains(marker)) {
        return marker;
      }
    }
    return null;
  }

  private static boolean isBinaryClassName(final String name) {
    return name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
  }
}
