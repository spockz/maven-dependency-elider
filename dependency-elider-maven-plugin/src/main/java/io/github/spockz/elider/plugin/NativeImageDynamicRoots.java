/* WHY: Validates and extracts only supported Graal native-image class/resource roots. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Parses supported native-image metadata without accepting unknown root formats. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class NativeImageDynamicRoots {
  /** Root of the native-image metadata namespace in dependency archives. */
  static final String PREFIX = "META-INF/native-image/";

  private NativeImageDynamicRoots() {}

  static boolean isNativeImageClassConfig(final String name) {
    return NativeImageClassConfig.isNativeImageClassConfig(name);
  }

  static boolean isNativeImageResourceConfig(final String name) {
    return NativeImageResourceConfig.isNativeImageResourceConfig(name);
  }

  static boolean isNativeImageSbom(final String name) {
    return (PREFIX + "sbom.json").equals(name) || name.endsWith("/sbom.json");
  }

  static boolean readNativeImageProperties(
      final JarFile archive, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    final Properties properties = new Properties();
    try (InputStream input = archive.getInputStream(propertiesEntry)) {
      properties.load(input);
    }
    if (properties.size() != 1 || !properties.containsKey("Args")) {
      throw new IOException("Unsupported native-image properties in " + propertiesEntry.getName());
    }
    final String args = properties.getProperty("Args").trim();
    if (args.isEmpty() || args.contains("\"") || args.contains("'")) {
      throw new IOException("Unsupported native-image Args in " + propertiesEntry.getName());
    }
    boolean declaresClassRoots = false;
    for (final String argument : args.split("\\s+")) {
      declaresClassRoots |= readNativeImageArgument(argument, archive, propertiesEntry, roots);
    }
    return declaresClassRoots;
  }

  private static boolean readNativeImageArgument(
      final String argument,
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots)
      throws IOException {
    if (argument.startsWith("-H:ReflectionConfigurationResources=")) {
      readNativeImageConfigResources(
          archive,
          propertiesEntry.getName(),
          argument.substring("-H:ReflectionConfigurationResources=".length()),
          true,
          roots);
      return true;
    }
    if (argument.startsWith("-H:ResourceConfigurationResources=")) {
      readNativeImageConfigResources(
          archive,
          propertiesEntry.getName(),
          argument.substring("-H:ResourceConfigurationResources=".length()),
          false,
          roots);
      return false;
    }
    if ("--enable-http".equals(argument) || "--enable-https".equals(argument)) {
      return false;
    }
    if (argument.startsWith("--initialize-at-build-time=")) {
      return readNativeImageClassNames(
          argument.substring("--initialize-at-build-time=".length()), propertiesEntry, roots);
    }
    if (argument.startsWith("--features=")) {
      return readNativeImageClassNames(
          argument.substring("--features=".length()), propertiesEntry, roots);
    }
    throw new IOException("Unsupported native-image Args in " + propertiesEntry.getName());
  }

  private static boolean readNativeImageClassNames(
      final String values, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    if (values.isBlank()) {
      throw new IOException("Native-image class list is empty: " + propertiesEntry.getName());
    }
    for (final String className : values.split(",", -1)) {
      if (!className.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*")) {
        throw new IOException(
            "Unsupported native-image class name in "
                + propertiesEntry.getName()
                + ": "
                + className);
      }
      roots.add(className);
    }
    return true;
  }

  private static void readNativeImageConfigResources(
      final JarFile archive,
      final String propertiesEntry,
      final String references,
      final boolean classConfig,
      final Set<String> roots)
      throws IOException {
    if (references.isBlank()) {
      throw new IOException(
          "Native-image configuration resource path is empty: " + propertiesEntry);
    }
    for (final String reference : references.split(",", -1)) {
      final String path = resolveNativeImageConfigPath(propertiesEntry, reference.trim());
      final JarEntry configEntry = archive.getJarEntry(path);
      if (configEntry == null || configEntry.isDirectory()) {
        throw new IOException("Native-image configuration resource is missing: " + path);
      }
      if (classConfig) {
        NativeImageClassConfig.readNativeImageClassConfig(archive, path, roots);
      } else {
        NativeImageResourceConfig.readNativeImageResourceConfig(archive, path, roots);
      }
    }
  }

  private static String resolveNativeImageConfigPath(
      final String propertiesEntry, final String reference) throws IOException {
    final String relative = reference.startsWith("${.}/") ? reference.substring(5) : reference;
    if (relative.isBlank()
        || relative.startsWith("/")
        || relative.contains("\\")
        || java.util.Arrays.stream(relative.split("/", -1))
            .anyMatch(
                segment -> "".equals(segment) || ".".equals(segment) || "..".equals(segment))) {
      throw new IOException(
          "Unsupported native-image configuration path in " + propertiesEntry + ": " + reference);
    }
    return propertiesEntry.substring(0, propertiesEntry.lastIndexOf('/') + 1) + relative;
  }

  static boolean isBinaryClassName(final String name) {
    return name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
  }
}
