/* WHY: Keeps Spring metadata validation separate from archive and native-image dispatch. */

package io.github.spockz.elider.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/** Parses supported Spring class-name metadata into conservative roots. */
final class SpringMetadataRoots {
  /** WHY: Spring condition keys use a fixed ASCII marker grammar. */
  private static final Pattern CONDITIONAL_MARKER = Pattern.compile("Conditional[A-Za-z0-9_$]+");

  /** WHY: Ordering suffixes are the same for every metadata entry. */
  private static final List<String> ORDERING_MARKERS =
      List.of(".AutoConfigureBefore", ".AutoConfigureAfter", ".AutoConfigureOrder");

  /** WHY: Accepted web application values are fixed across metadata entries. */
  private static final Set<String> WEB_APPLICATION_TYPES = Set.of("", "SERVLET", "REACTIVE");

  private SpringMetadataRoots() {
    throw new AssertionError("No instances");
  }

  /* package */ static boolean readFactories(final InputStream input, final Set<String> roots)
      throws IOException {
    final Properties factories = new Properties();
    try (InputStream stream = input) {
      factories.load(stream);
    }
    for (final String key : factories.stringPropertyNames()) {
      final String factory = key.trim();
      if (!AsciiBinaryClassName.isValid(factory)) {
        throw new IOException("Malformed Spring factory interface name: " + key);
      }
      roots.add(factory);
      for (final String provider : factories.getProperty(key).split(",")) {
        final String className = provider.trim();
        if (!AsciiBinaryClassName.isValid(className)) {
          throw new IOException("Malformed Spring factory implementation: " + provider);
        }
        roots.add(className);
      }
    }
    return true;
  }

  /* package */ static void readImports(
      final InputStream input, final Set<String> roots, final String entryName) throws IOException {
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line = reader.readLine();
      while (line != null) {
        final String className = line.split("#", 2)[0].trim();
        if (!className.isEmpty()) {
          if (!AsciiBinaryClassName.isValid(className)) {
            throw new IOException("Malformed Spring AutoConfiguration import in " + entryName);
          }
          roots.add(className);
        }
        line = reader.readLine();
      }
    }
  }

  /* package */ static void readMetadata(
      final InputStream input, final Set<String> roots, final Set<String> jarClasses)
      throws IOException {
    final Properties metadata = new Properties();
    try (InputStream stream = input) {
      metadata.load(stream);
    }
    for (final String propertyKey : metadata.stringPropertyNames()) {
      readMetadataEntry(propertyKey, metadata.getProperty(propertyKey), roots, jarClasses);
    }
  }

  private static void readMetadataEntry(
      final String key, final String value, final Set<String> roots, final Set<String> jarClasses)
      throws IOException {
    if (jarClasses.contains(key)) {
      if (!value.isEmpty()) {
        throw new IOException("Unsupported Spring autoconfigure metadata key: " + key);
      }
      roots.add(key);
      return;
    }
    final String marker = metadataMarker(key, jarClasses);
    if (marker == null) {
      throw new IOException("Unsupported Spring autoconfigure metadata key: " + key);
    }
    final int markerIndex = key.lastIndexOf(marker);
    final String owner = key.substring(0, markerIndex);
    if (!jarClasses.contains(owner)) {
      throw new IOException("Spring autoconfigure metadata owner is not in the JAR: " + owner);
    }
    roots.add(owner);
    readMetadataValue(key, marker, markerIndex, value, roots);
  }

  private static void readMetadataValue(
      final String key,
      final String marker,
      final int markerIndex,
      final String value,
      final Set<String> roots)
      throws IOException {
    if (marker.endsWith("Before") || marker.endsWith("After")) {
      readClassValues(value, "Unsupported Spring autoconfigure metadata value: ", roots);
    } else if (marker.endsWith("Order")) {
      readOrder(value);
    } else if (marker.endsWith("Conditional")) {
      readConditionalValue(key, marker, markerIndex, value, roots);
    }
  }

  private static void readConditionalValue(
      final String key,
      final String marker,
      final int markerIndex,
      final String value,
      final Set<String> roots)
      throws IOException {
    final String condition = key.substring(markerIndex + marker.length());
    if (classValuedCondition(condition) && !value.isBlank()) {
      readClassValues(value, "Unsupported Spring autoconfigure class value: ", roots);
    } else if (key.endsWith(".ConditionalOnWebApplication")
        && !WEB_APPLICATION_TYPES.contains(value)) {
      throw new IOException("Unsupported Spring web application condition value: " + value);
    }
  }

  private static void readClassValues(
      final String value, final String errorPrefix, final Set<String> roots) throws IOException {
    for (final String candidate : value.split("[,;\\s]+")) {
      if (!AsciiBinaryClassName.isValid(candidate)) {
        throw new IOException(errorPrefix + candidate);
      }
      roots.add(candidate);
    }
  }

  private static void readOrder(final String value) throws IOException {
    try {
      Integer.parseInt(value);
    } catch (final NumberFormatException exception) {
      throw new IOException("Unsupported Spring autoconfigure order value: " + value, exception);
    }
  }

  private static boolean classValuedCondition(final String condition) {
    return condition.startsWith("OnClass")
        || condition.startsWith("OnMissingClass")
        || condition.startsWith("OnBean")
        || condition.startsWith("OnMissingBean")
        || condition.startsWith("OnSingleCandidate");
  }

  private static String metadataMarker(final String key, final Set<String> jarClasses) {
    for (final String suffix : ORDERING_MARKERS) {
      if (key.endsWith(suffix)) {
        return suffix;
      }
    }
    final int conditionIndex = key.lastIndexOf(".Conditional");
    if (conditionIndex >= 0
        && jarClasses.contains(key.substring(0, conditionIndex))
        && CONDITIONAL_MARKER.matcher(key.substring(conditionIndex + 1)).matches()) {
      return ".Conditional";
    }
    return null;
  }
}
