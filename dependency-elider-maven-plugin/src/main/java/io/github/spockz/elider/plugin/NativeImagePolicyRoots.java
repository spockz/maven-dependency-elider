/* WHY: Converts audited reachability policies and resource regexes into conservative roots. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** Reads broad inclusion policies and resource-selection patterns. */
final class NativeImagePolicyRoots {
  /** Exact enabled forms that select the complete indexed dependency scope. */
  private static final Set<String> ENABLED_BROAD_POLICIES =
      Set.of(
          "-H:+EnableAllSecurityServices",
          "--enable-all-security-services",
          "-H:+AddAllFileSystemProviders",
          "-H:+IncludeAllLocales");

  /** Disabled broad forms never subtract other inputs' roots. */
  private static final Set<String> DISABLED_BROAD_POLICIES =
      Set.of(
          "-H:-EnableAllSecurityServices",
          "-H:-AddAllFileSystemProviders",
          "-H:-IncludeAllLocales");

  /** Registration toggles are validated without direct class roots. */
  private static final Set<String> SECURITY_FEATURE_POLICIES =
      Set.of("-H:+EnableSecurityServicesFeature", "-H:-EnableSecurityServicesFeature");

  /** Collects patterns until exclusions can be applied across the invocation. */
  /* package */ static final class ResourcePatterns {
    /** Include selectors that may add class roots and providers. */
    private final List<Pattern> includes = new ArrayList<>();

    /** Exclude selectors applied before any include selector. */
    private final List<Pattern> excludes = new ArrayList<>();

    /* package */
    void include(final Pattern pattern) {
      includes.add(pattern);
    }

    /* package */
    void exclude(final Pattern pattern) {
      excludes.add(pattern);
    }

    /* package */
    ResourcePatternSelection snapshot() {
      return new ResourcePatternSelection(includes, excludes);
    }
  }

  /** Immutable option values carried from archive scans into invocation aggregation. */
  /* package */ record ResourcePatternSelection(List<Pattern> includes, List<Pattern> excludes) {
    ResourcePatternSelection {
      includes = List.copyOf(includes);
      excludes = List.copyOf(excludes);
    }

    /* package */
    static ResourcePatternSelection empty() {
      return new ResourcePatternSelection(List.of(), List.of());
    }
  }

  /* package */
  static boolean applyResourcePatterns(
      final Iterable<ResourcePatternSelection> selections,
      final NativeImageScanContext scanContext,
      final Set<String> roots,
      final Set<java.nio.file.Path> resourceProviders)
      throws IOException {
    final List<Pattern> includes = new ArrayList<>();
    final List<Pattern> excludes = new ArrayList<>();
    for (final ResourcePatternSelection selection : selections) {
      includes.addAll(selection.includes());
      excludes.addAll(selection.excludes());
    }
    return !includes.isEmpty()
        && NativeImageResourcePatternMatcher.apply(
            includes, excludes, scanContext.resourceIndex(), roots, resourceProviders);
  }

  private NativeImagePolicyRoots() {
    throw new AssertionError("static native-image policy reader");
  }

  /* package */
  static Optional<Boolean> read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final ResourcePatterns resourcePatterns)
      throws IOException {
    if (isBareRecognizedOption(argument)) {
      throw new IOException(
          "Native-image policy option has no value in "
              + propertiesEntry.getName()
              + ": "
              + argument);
    }
    final Optional<Boolean> broadPolicy = readBroadPolicy(argument, roots, scanContext);
    if (broadPolicy.isPresent()) {
      return broadPolicy;
    }
    final Optional<Boolean> urlPolicy =
        readUrlPolicy(argument, propertiesEntry, roots, scanContext);
    if (urlPolicy.isPresent()) {
      return urlPolicy;
    }
    return readResourcePattern(argument, propertiesEntry, resourcePatterns);
  }

  private static Optional<Boolean> readBroadPolicy(
      final String argument, final Set<String> roots, final NativeImageScanContext scanContext)
      throws IOException {
    if (ENABLED_BROAD_POLICIES.contains(argument)) {
      roots.addAll(scanContext.logicalClasses(Optional.empty()));
      return Optional.of(true);
    }
    return DISABLED_BROAD_POLICIES.contains(argument)
            || SECURITY_FEATURE_POLICIES.contains(argument)
        ? Optional.of(false)
        : Optional.empty();
  }

  private static Optional<Boolean> readUrlPolicy(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext)
      throws IOException {
    if (argument.startsWith("-H:EnableURLProtocols=")
        || argument.startsWith("--enable-url-protocols=")) {
      validateProtocols(value(argument), propertiesEntry);
      roots.addAll(scanContext.logicalClasses(Optional.empty()));
      return Optional.of(true);
    }
    if (argument.startsWith("-H:DisableURLProtocols=")) {
      validateProtocols(value(argument), propertiesEntry);
      return Optional.of(false);
    }
    return Optional.empty();
  }

  private static Optional<Boolean> readResourcePattern(
      final String argument,
      final JarEntry propertiesEntry,
      final ResourcePatterns resourcePatterns)
      throws IOException {
    if (argument.startsWith("-H:IncludeResources=")) {
      compilePattern(value(argument), argument, propertiesEntry)
          .ifPresent(resourcePatterns::include);
      return Optional.of(false);
    }
    if (argument.startsWith("-H:ExcludeResources=")) {
      compilePattern(value(argument), argument, propertiesEntry)
          .ifPresent(resourcePatterns::exclude);
      return Optional.of(false);
    }
    return Optional.empty();
  }

  /* package */
  static boolean requiresArtifactRetention(final String argument) {
    return ENABLED_BROAD_POLICIES.contains(argument)
        || DISABLED_BROAD_POLICIES.contains(argument)
        || SECURITY_FEATURE_POLICIES.contains(argument)
        || argument.startsWith("-H:EnableURLProtocols=")
        || argument.startsWith("-H:DisableURLProtocols=")
        || argument.startsWith("--enable-url-protocols=")
        || argument.startsWith("-H:IncludeResources=")
        || argument.startsWith("-H:ExcludeResources=");
  }

  private static boolean isBareRecognizedOption(final String argument) {
    return "-H:EnableURLProtocols".equals(argument)
        || "-H:DisableURLProtocols".equals(argument)
        || "--enable-url-protocols".equals(argument)
        || "-H:IncludeResources".equals(argument)
        || "-H:ExcludeResources".equals(argument);
  }

  private static String value(final String argument) {
    return argument.substring(argument.indexOf('=') + 1);
  }

  private static Optional<Pattern> compilePattern(
      final String value, final String argument, final JarEntry propertiesEntry)
      throws IOException {
    if (value.isEmpty()) {
      throw new IOException(
          "Native-image resource pattern has no value in " + propertiesEntry.getName());
    }
    final int selectorSeparator = value.indexOf(':');
    final String expression;
    final String selector;
    if (selectorSeparator >= 0) {
      selector = value.substring(0, selectorSeparator);
      expression = value.substring(selectorSeparator + 1);
    } else {
      selector = null;
      expression = value;
    }
    try {
      final Pattern pattern = Pattern.compile(expression);
      return selector == null || "ALL-UNNAMED".equals(selector)
          ? Optional.of(pattern)
          : Optional.empty();
    } catch (final PatternSyntaxException exception) {
      throw new IOException(
          "Malformed native-image resource pattern in "
              + propertiesEntry.getName()
              + ": "
              + argument,
          exception);
    }
  }

  private static void validateProtocols(final String value, final JarEntry propertiesEntry)
      throws IOException {
    if (value.isEmpty()) {
      throw new IOException(
          "Native-image URL protocol option has no protocol in " + propertiesEntry.getName());
    }
    for (final String protocol : value.split(",", -1)) {
      if (protocol.isEmpty()) {
        throw new IOException(
            "Malformed native-image URL protocol in "
                + propertiesEntry.getName()
                + ": "
                + protocol);
      }
    }
  }
}
