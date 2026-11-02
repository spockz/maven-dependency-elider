/* WHY: Dispatches audited direct-root switches separately from metadata resource options. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;

/** Reads explicitly listed Graal classes without changing unknown-option policy. */
final class NativeImageDirectRoots {
  /** Class-list switches share parsing and validation behavior. */
  private static final List<String> NAMED_CLASS_OPTIONS =
      List.of(
          "--features=",
          "-H:Features=",
          "--trace-class-initialization=",
          "-H:TraceClassInitialization=",
          "--trace-object-instantiation=",
          "-H:TraceObjectInstantiation=",
          "-H:AdditionalSecurityProviders=",
          "-H:AdditionalSecurityServiceTypes=");

  /** Single-class switches share class-name validation. */
  private static final List<String> SINGLE_CLASS_OPTIONS = List.of("-H:Class=", "--main-class=");

  /** Root-taking options that require an attached value. */
  private static final Set<String> BARE_OPTIONS = bareOptions();

  private NativeImageDirectRoots() {}

  /* package */
  static Optional<NativeImageDynamicRoots.ArgumentResult> read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<java.nio.file.Path> resourceProviders,
      final Set<NativeImageConsumedInput> consumedInputs,
      final NativeImagePolicyRoots.ResourcePatterns resourcePatterns)
      throws IOException {
    final Optional<NativeImageDynamicRoots.ArgumentResult> policy =
        readPolicy(argument, propertiesEntry, roots, scanContext, resourcePatterns);
    if (policy.isPresent()) {
      return policy;
    }
    final Optional<Boolean> initialization =
        NativeImageInitializationRoots.read(argument, propertiesEntry, roots, scanContext);
    if (initialization.isPresent()) {
      return roots(initialization);
    }
    final Optional<Boolean> linkAtBuildTime =
        NativeImageLinkAtBuildTimeRoots.read(
            argument, propertiesEntry, roots, scanContext, consumedInputs);
    if (linkAtBuildTime.isPresent()) {
      return roots(linkAtBuildTime);
    }
    rejectBareOptions(argument, propertiesEntry);
    final Optional<Boolean> classOptions = readNamedClassOptions(argument, propertiesEntry, roots);
    if (classOptions.isPresent()) {
      return roots(classOptions);
    }
    final Optional<Boolean> singleClass = readSingleClassOption(argument, propertiesEntry, roots);
    if (singleClass.isPresent()) {
      return roots(singleClass);
    }
    return readResourceBundleOption(
        argument, propertiesEntry, roots, scanContext, resourceProviders);
  }

  private static void rejectBareOptions(final String argument, final JarEntry propertiesEntry)
      throws IOException {
    if (BARE_OPTIONS.contains(argument)) {
      throw new IOException(
          "Native-image root option has no value in "
              + propertiesEntry.getName()
              + ": "
              + argument);
    }
  }

  private static Optional<NativeImageDynamicRoots.ArgumentResult> readPolicy(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final NativeImagePolicyRoots.ResourcePatterns resourcePatterns)
      throws IOException {
    return NativeImagePolicyRoots.read(
        argument, propertiesEntry, roots, scanContext, resourcePatterns);
  }

  private static Optional<Boolean> readNamedClassOptions(
      final String argument, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    for (final String option : NAMED_CLASS_OPTIONS) {
      if (argument.startsWith(option)) {
        return namedList(argument, option, propertiesEntry, roots);
      }
    }
    return Optional.empty();
  }

  private static Optional<Boolean> readSingleClassOption(
      final String argument, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    for (final String option : SINGLE_CLASS_OPTIONS) {
      if (argument.startsWith(option)) {
        return Optional.of(
            NativeImageClassRootParsing.readSingleClass(
                argument.substring(option.length()), propertiesEntry, roots));
      }
    }
    return Optional.empty();
  }

  private static Optional<NativeImageDynamicRoots.ArgumentResult> readResourceBundleOption(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<java.nio.file.Path> resourceProviders)
      throws IOException {
    if (!argument.startsWith("-H:IncludeResourceBundles=")) {
      return Optional.empty();
    }
    return Optional.of(
        new NativeImageDynamicRoots.ArgumentResult(
            NativeImageClassRootParsing.readResourceBundles(
                argument.substring("-H:IncludeResourceBundles=".length()),
                propertiesEntry,
                roots,
                scanContext,
                resourceProviders),
            true));
  }

  private static Optional<NativeImageDynamicRoots.ArgumentResult> roots(
      final Optional<Boolean> declaresClassRoots) {
    return declaresClassRoots.map(
        declares -> new NativeImageDynamicRoots.ArgumentResult(declares, false));
  }

  private static Optional<Boolean> namedList(
      final String argument,
      final String prefix,
      final JarEntry propertiesEntry,
      final Set<String> roots)
      throws IOException {
    return Optional.of(
        NativeImageClassRootParsing.readNamedList(
            argument.substring(prefix.length()), propertiesEntry, roots));
  }

  private static Set<String> bareOptions() {
    final Set<String> options = new HashSet<>(Set.of("-H:IncludeResourceBundles"));
    for (final String option : NAMED_CLASS_OPTIONS) {
      options.add(option.substring(0, option.length() - 1));
    }
    for (final String option : SINGLE_CLASS_OPTIONS) {
      options.add(option.substring(0, option.length() - 1));
    }
    return Set.copyOf(options);
  }
}
