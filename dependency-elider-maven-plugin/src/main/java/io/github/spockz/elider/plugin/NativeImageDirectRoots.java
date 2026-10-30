/* WHY: Dispatches audited direct-root switches separately from metadata resource options. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;

/** Reads explicitly listed Graal classes without changing unknown-option policy. */
final class NativeImageDirectRoots {
  /** Root-taking options that require an attached value. */
  private static final Set<String> BARE_OPTIONS =
      Set.of(
          "--features",
          "-H:Features",
          "-H:Class",
          "--main-class",
          "--trace-class-initialization",
          "-H:TraceClassInitialization",
          "--trace-object-instantiation",
          "-H:TraceObjectInstantiation",
          "-H:AdditionalSecurityProviders",
          "-H:AdditionalSecurityServiceTypes",
          "-H:IncludeResourceBundles");

  private NativeImageDirectRoots() {}

  /* package */
  static Optional<Boolean> read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext,
      final Set<java.nio.file.Path> resourceProviders)
      throws IOException {
    final Optional<Boolean> initialization =
        NativeImageInitializationRoots.read(argument, propertiesEntry, roots, scanContext);
    if (initialization.isPresent()) {
      return initialization;
    }
    if ("-H:ReflectionConfigurationResources".equals(argument)
        || "-H:ResourceConfigurationResources".equals(argument)
        || BARE_OPTIONS.contains(argument)) {
      throw new IOException(
          "Native-image root option has no value in "
              + propertiesEntry.getName()
              + ": "
              + argument);
    }
    final Optional<Boolean> classOptions = readNamedClassOptions(argument, propertiesEntry, roots);
    if (classOptions.isPresent()) {
      return classOptions;
    }
    final Optional<Boolean> singleClass = readSingleClassOption(argument, propertiesEntry, roots);
    if (singleClass.isPresent()) {
      return singleClass;
    }
    return readResourceBundleOption(
        argument, propertiesEntry, roots, scanContext, resourceProviders);
  }

  private static Optional<Boolean> readNamedClassOptions(
      final String argument, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    if (argument.startsWith("--features=")) {
      return namedList(argument, "--features=", propertiesEntry, roots);
    }
    if (argument.startsWith("-H:Features=")) {
      return namedList(argument, "-H:Features=", propertiesEntry, roots);
    }
    if (argument.startsWith("--trace-class-initialization=")) {
      return namedList(argument, "--trace-class-initialization=", propertiesEntry, roots);
    }
    if (argument.startsWith("-H:TraceClassInitialization=")) {
      return namedList(argument, "-H:TraceClassInitialization=", propertiesEntry, roots);
    }
    if (argument.startsWith("--trace-object-instantiation=")) {
      return namedList(argument, "--trace-object-instantiation=", propertiesEntry, roots);
    }
    if (argument.startsWith("-H:TraceObjectInstantiation=")) {
      return namedList(argument, "-H:TraceObjectInstantiation=", propertiesEntry, roots);
    }
    if (argument.startsWith("-H:AdditionalSecurityProviders=")) {
      return namedList(argument, "-H:AdditionalSecurityProviders=", propertiesEntry, roots);
    }
    if (argument.startsWith("-H:AdditionalSecurityServiceTypes=")) {
      return namedList(argument, "-H:AdditionalSecurityServiceTypes=", propertiesEntry, roots);
    }
    return Optional.empty();
  }

  private static Optional<Boolean> readSingleClassOption(
      final String argument, final JarEntry propertiesEntry, final Set<String> roots)
      throws IOException {
    if (argument.startsWith("-H:Class=")) {
      return Optional.of(
          NativeImageClassRootParsing.readSingleClass(
              argument.substring("-H:Class=".length()), propertiesEntry, roots));
    }
    if (argument.startsWith("--main-class=")) {
      return Optional.of(
          NativeImageClassRootParsing.readSingleClass(
              argument.substring("--main-class=".length()), propertiesEntry, roots));
    }
    return Optional.empty();
  }

  private static Optional<Boolean> readResourceBundleOption(
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
        NativeImageClassRootParsing.readResourceBundles(
            argument.substring("-H:IncludeResourceBundles=".length()),
            propertiesEntry,
            roots,
            scanContext,
            resourceProviders));
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
}
