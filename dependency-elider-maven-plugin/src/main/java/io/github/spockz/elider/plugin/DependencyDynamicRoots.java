/* WHY: Finds class names declared by dependency-local dynamic loading metadata before a JAR is
 * trimmed, since ordinary bytecode references cannot describe SPI or native-image lookups. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Enumeration;
import java.util.LinkedHashSet;
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
  "PMD.AvoidDeeplyNestedIfStmts"
})
final class DependencyDynamicRoots {
  private static final String SERVICES = "META-INF/services/";
  private static final String NATIVE_IMAGE = "META-INF/native-image/";
  private static final ObjectMapper JSON = new ObjectMapper();

  private DependencyDynamicRoots() {}

  static Set<String> read(final java.nio.file.Path jar) throws IOException {
    final Set<String> roots = new LinkedHashSet<>();
    try (JarFile archive = new JarFile(jar.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory()) {
          continue;
        }
        final String name = entry.getName();
        if (name.startsWith(SERVICES)) {
          final String service = name.substring(SERVICES.length());
          if (service.isBlank() || service.contains("/")) {
            throw new IOException("Unsupported service descriptor path: " + name);
          }
          roots.add(service);
          try (var reader =
              new java.io.BufferedReader(
                  new java.io.InputStreamReader(
                      archive.getInputStream(entry), java.nio.charset.StandardCharsets.UTF_8))) {
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
        }
      }
    }
    return Set.copyOf(roots);
  }
}
