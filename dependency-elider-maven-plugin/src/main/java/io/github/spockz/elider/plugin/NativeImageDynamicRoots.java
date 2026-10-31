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

  record PropertiesResult(
      boolean declaresClassRoots,
      boolean requiresArtifactRetention,
      Set<Path> resourceProviders,
      Set<NativeImageConsumedInput> consumedInputs,
      NativeImagePolicyRoots.ResourcePatternSelection resourcePatterns,
      NativeImageServiceLoaderPolicy.Selection serviceLoaderPolicy) {}

  static PropertiesResult readNativeImagePropertiesDetailed(
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs)
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
    final NativeImagePolicyRoots.ResourcePatterns resourcePatterns =
        new NativeImagePolicyRoots.ResourcePatterns();
    final NativeImageServiceLoaderPolicy.Builder serviceLoaderPolicy =
        new NativeImageServiceLoaderPolicy.Builder();
    for (final String argument : arguments) {
      NativeImageIndirectionGuard.validate(argument);
      if (NativeImageServiceLoaderPolicy.read(argument, propertiesEntry, serviceLoaderPolicy)) {
        requiresArtifactRetention = true;
        continue;
      }
      declaresClassRoots |=
          readNativeImageArgument(
              argument,
              archive,
              propertiesEntry,
              roots,
              scanContext,
              resourceProviders,
              consumedInputs,
              resourcePatterns);
      requiresArtifactRetention |= isConfigurationResourceArgument(argument);
      requiresArtifactRetention |= NativeImagePolicyRoots.requiresArtifactRetention(argument);
    }
    return new PropertiesResult(
        declaresClassRoots,
        requiresArtifactRetention,
        Set.copyOf(resourceProviders),
        Set.copyOf(consumedInputs),
        resourcePatterns.snapshot(),
        serviceLoaderPolicy.snapshot());
  }

  private static boolean isConfigurationResourceArgument(final String argument) {
    return NativeImageConfigurationPointers.isPointer(argument)
        || argument.startsWith("-H:IncludeResourceBundles=");
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

  private static boolean readNativeImageArgument(
      final String argument,
      final JarFile archive,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs,
      final NativeImagePolicyRoots.ResourcePatterns descriptorSelections)
      throws IOException {
    final java.util.Optional<Boolean> pointer =
        NativeImageConfigurationPointers.read(
            argument,
            archive,
            propertiesEntry,
            roots,
            scanContext,
            resourceProviders,
            consumedInputs,
            descriptorSelections);
    if (pointer.isPresent()) {
      return pointer.orElseThrow();
    }
    final java.util.Optional<Boolean> directRoot =
        NativeImageDirectRoots.read(
            argument,
            propertiesEntry,
            roots,
            scanContext,
            resourceProviders,
            consumedInputs,
            descriptorSelections);
    if (directRoot.isPresent()) {
      return directRoot.get();
    }
    return false;
  }

  static String resolveNativeImageConfigPath(
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
    if (name == null || name.isEmpty()) {
      return false;
    }
    for (final String segment : name.split("\\.", -1)) {
      if (!isJavaIdentifierSegment(segment)) {
        return false;
      }
    }
    return true;
  }

  private static boolean isJavaIdentifierSegment(final String segment) {
    return !segment.isEmpty()
        && Character.isJavaIdentifierStart(segment.codePointAt(0))
        && segment.codePoints().skip(1).allMatch(Character::isJavaIdentifierPart);
  }
}
