/* WHY: Validates and extracts only supported Graal native-image class/resource roots. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Parses supported native-image metadata without accepting unknown root formats. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.GodClass"})
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

  record UnsupportedArgument(String entry, String name, String fullArgument) {}

  record PropertiesResult(
      boolean declaresClassRoots,
      boolean requiresArtifactRetention,
      List<UnsupportedArgument> unsupportedArguments,
      Set<Path> resourceProviders) {}

  @SuppressWarnings("PMD.CyclomaticComplexity")
  static PropertiesResult readNativeImagePropertiesDetailed(
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final Set<String> allowedArguments,
      final boolean failOnUnsupported,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders)
      throws IOException {
    final Properties properties = new Properties();
    try (InputStream input = archive.getInputStream(propertiesEntry)) {
      properties.load(input);
    }
    if (properties.size() != 1 || !properties.containsKey("Args")) {
      throw new IOException("Unsupported native-image properties in " + propertiesEntry.getName());
    }
    final List<String> arguments = tokenize(properties.getProperty("Args"));
    if (arguments.isEmpty()) {
      throw new IOException("Unsupported native-image Args in " + propertiesEntry.getName());
    }
    boolean declaresClassRoots = false;
    boolean requiresArtifactRetention = false;
    final List<UnsupportedArgument> unsupported = new ArrayList<>();
    for (final String argument : arguments) {
      try {
        declaresClassRoots |=
            readNativeImageArgument(
                argument, archive, propertiesEntry, roots, scanContext, resourceProviders);
        requiresArtifactRetention |= isConfigurationResourceArgument(argument);
      } catch (final UnknownNativeImageArgument exception) {
        if (allowedArguments.contains(argumentName(argument))) {
          continue;
        }
        if (failOnUnsupported) {
          throw unsupportedArgument(propertiesEntry, argument, exception);
        }
        unsupported.add(
            new UnsupportedArgument(propertiesEntry.getName(), argumentName(argument), argument));
      }
    }
    return new PropertiesResult(
        declaresClassRoots,
        requiresArtifactRetention,
        List.copyOf(unsupported),
        Set.copyOf(resourceProviders));
  }

  private static boolean isConfigurationResourceArgument(final String argument) {
    return argument.startsWith("-H:ReflectionConfigurationResources=")
        || argument.startsWith("-H:ResourceConfigurationResources=");
  }

  /** Scans quote-delimited tokens while preserving non-syntactic characters verbatim. */
  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.ConfusingTernary",
    "PMD.AvoidDeeplyNestedIfStmts"
  })
  private static List<String> tokenize(final String input) throws IOException {
    final List<String> tokens = new ArrayList<>();
    final StringBuilder token = new StringBuilder();
    char quote = 0;
    for (int index = 0; index < input.length(); index++) {
      final char value = input.charAt(index);
      if (quote != 0) {
        if (value == quote) {
          if (token.length() == 0) {
            throw new IOException("Empty token in native-image Args");
          }
          quote = 0;
        } else {
          token.append(value);
        }
      } else if (value == '\'' || value == '"') {
        quote = value;
      } else if (Character.isWhitespace(value)) {
        addToken(tokens, token);
      } else {
        token.append(value);
      }
    }
    if (quote != 0) {
      throw new IOException("Unmatched quote in native-image Args");
    }
    addToken(tokens, token);
    return tokens;
  }

  private static void addToken(final List<String> tokens, final StringBuilder token)
      throws IOException {
    if (token.length() > 0) {
      tokens.add(token.toString());
      token.setLength(0);
    }
  }

  private static String argumentName(final String argument) {
    final int equals = argument.indexOf('=');
    return equals < 0 ? argument : argument.substring(0, equals);
  }

  private static IOException unsupportedArgument(
      final JarEntry entry, final String argument, final IOException cause) {
    final String name = argumentName(argument);
    return new IOException(
        "Unsupported native-image argument '"
            + name
            + "' in "
            + entry.getName()
            + " (full argument: '"
            + argument
            + "'). Inspect the property in the dependency archive. "
            + "If it does not declare dynamic class roots, add its name to "
            + "<allowedNativeImageArgs> in pom.xml:\n"
            + "  <configuration>\n    <allowedNativeImageArgs>\n      <allowedNativeImageArg>"
            + name
            + "</allowedNativeImageArg>\n    </allowedNativeImageArgs>\n  </configuration>\n"
            + "Or via CLI: -Delide.allowedNativeImageArgs="
            + name,
        cause);
  }

  /** Separates unknown options from malformed modeled options. */
  private static final class UnknownNativeImageArgument extends IOException {
    private static final long serialVersionUID = 1L;
  }

  @SuppressWarnings("PMD.CyclomaticComplexity")
  private static boolean readNativeImageArgument(
      final String argument,
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders)
      throws IOException {
    if (argument.startsWith("-H:ReflectionConfigurationResources=")) {
      readNativeImageConfigResources(
          archive,
          propertiesEntry.getName(),
          argument.substring("-H:ReflectionConfigurationResources=".length()),
          NativeImageDescriptorKind.REFLECTION,
          roots,
          scanContext,
          resourceProviders);
      return true;
    }
    if ("-H:ReflectionConfigurationResources".equals(argument)
        || "-H:ResourceConfigurationResources".equals(argument)
        || "--features".equals(argument)) {
      throw new IOException(
          "Native-image root option has no value in "
              + propertiesEntry.getName()
              + ": "
              + argument);
    }
    if (argument.startsWith("-H:ResourceConfigurationResources=")) {
      readNativeImageConfigResources(
          archive,
          propertiesEntry.getName(),
          argument.substring("-H:ResourceConfigurationResources=".length()),
          NativeImageDescriptorKind.RESOURCES,
          roots,
          scanContext,
          resourceProviders);
      return false;
    }
    if ("--enable-http".equals(argument) || "--enable-https".equals(argument)) {
      return false;
    }
    if (argument.startsWith("--initialize-at-build-time=")) {
      return readNativeImageClassNames(
          argument.substring("--initialize-at-build-time=".length()), propertiesEntry, roots);
    }
    if (argument.startsWith("--initialize-at-run-time=")) {
      return readNativeImageClassNames(
          argument.substring("--initialize-at-run-time=".length()), propertiesEntry, roots);
    }
    if ("--initialize-at-build-time".equals(argument)
        || "--initialize-at-run-time".equals(argument)) {
      return false;
    }
    if (argument.startsWith("--features=")) {
      return readNativeImageClassNames(
          argument.substring("--features=".length()), propertiesEntry, roots);
    }
    if ("-H:+AddAllCharsets".equals(argument)
        || "-H:-AddAllCharsets".equals(argument)
        || "--report-unsupported-elements-at-runtime".equals(argument)) {
      return false;
    }
    throw new UnknownNativeImageArgument();
  }

  private static boolean readNativeImageClassNames(
      final String values, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    if (values.isBlank()) {
      return false;
    }
    boolean added = false;
    for (final String className : values.split(",", -1)) {
      final String trimmed = className.trim();
      if (trimmed.isEmpty()) {
        continue;
      }
      final String component = NativeImageTypeDescriptor.extractComponentClass(trimmed);
      if (component == null || component.isEmpty() || !isBinaryClassName(component)) {
        throw new IOException(
            "Unsupported native-image class name in " + propertiesEntry.getName() + ": " + trimmed);
      }
      roots.add(component);
      added = true;
    }
    return added;
  }

  private static void readNativeImageConfigResources(
      final JarFile archive,
      final String propertiesEntry,
      final String references,
      final NativeImageDescriptorKind kind,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders)
      throws IOException {
    if (references.isBlank()) {
      throw new IOException(
          "Native-image configuration resource path is empty: " + propertiesEntry);
    }
    for (final String reference : references.split(",", -1)) {
      final String trimmed = reference.trim();
      final boolean descriptorRelative = trimmed.startsWith("${.}/");
      final String path =
          resolveNativeImageConfigPath(propertiesEntry, trimmed, descriptorRelative);
      readNativeImageConfigResource(
          archive, path, descriptorRelative, kind, roots, scanContext, resourceProviders);
    }
  }

  private static void readNativeImageConfigResource(
      final JarFile archive,
      final String path,
      final boolean descriptorRelative,
      final NativeImageDescriptorKind kind,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders)
      throws IOException {
    final NativeImageScanContext.DescriptorReader reader =
        kind == NativeImageDescriptorKind.REFLECTION
            ? input -> NativeImageClassConfig.readNativeImageClassConfig(input, roots)
            : input -> NativeImageResourceConfig.readNativeImageResourceConfig(input, roots);
    final boolean found;
    try {
      found =
          descriptorRelative
              ? scanContext.readDescriptorRelativeResource(
                  archive, path, kind, reader, resourceProviders)
              : scanContext.readClasspathResource(path, kind, reader, resourceProviders);
    } catch (final IOException exception) {
      throw new IOException(
          "Cannot read native-image configuration resource: "
              + path
              + ": "
              + exception.getMessage(),
          exception);
    }
    if (!found) {
      throw new IOException("Native-image configuration resource is missing: " + path);
    }
  }

  private static String resolveNativeImageConfigPath(
      final String propertiesEntry, final String reference, final boolean descriptorRelative)
      throws IOException {
    final String relative = descriptorRelative ? reference.substring(5) : reference;
    if (relative.isBlank()
        || relative.startsWith("/")
        || relative.contains("\\")
        || java.util.Arrays.stream(relative.split("/", -1))
            .anyMatch(
                segment -> "".equals(segment) || ".".equals(segment) || "..".equals(segment))) {
      throw new IOException(
          "Unsupported native-image configuration path in " + propertiesEntry + ": " + reference);
    }
    return descriptorRelative
        ? propertiesEntry.substring(0, propertiesEntry.lastIndexOf('/') + 1) + relative
        : relative;
  }

  static boolean isBinaryClassName(final String name) {
    return name.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*");
  }
}
