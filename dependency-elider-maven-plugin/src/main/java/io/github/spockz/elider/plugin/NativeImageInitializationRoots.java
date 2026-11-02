/* WHY: Models audited initialization scopes and their strategy syntax. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;

/** Reads initialization arguments and expands class/package inventory targets. */
final class NativeImageInitializationRoots {
  /** Strategies recognized by the pinned Graal Native Image option parser. */
  private static final Set<String> STRATEGIES = Set.of("build_time", "rerun", "run_time");

  /** Option name whose suffix carries initialization targets and strategies. */
  private static final String CLASS_INITIALIZATION_OPTION = "-H:ClassInitialization";

  private NativeImageInitializationRoots() {}

  /* package */
  static Optional<Boolean> read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext)
      throws IOException {
    if (isBareScope(argument)) {
      return Optional.of(NativeImageClassRootParsing.addWholeInventory(scanContext, roots));
    }
    if (argument.startsWith("--initialize-at-build-time=")) {
      return Optional.of(
          readTargetList(
              argument.substring("--initialize-at-build-time=".length()),
              propertiesEntry,
              roots,
              scanContext));
    }
    if (argument.startsWith("--initialize-at-run-time=")) {
      return Optional.of(
          readTargetList(
              argument.substring("--initialize-at-run-time=".length()),
              propertiesEntry,
              roots,
              scanContext));
    }
    if (CLASS_INITIALIZATION_OPTION.equals(argument)) {
      throw new IOException(
          "Native-image root option has no value in "
              + propertiesEntry.getName()
              + ": "
              + argument);
    }
    if (argument.startsWith(CLASS_INITIALIZATION_OPTION + "=")) {
      return Optional.of(
          readClassInitialization(
              argument.substring(CLASS_INITIALIZATION_OPTION.length() + 1),
              propertiesEntry,
              roots,
              scanContext));
    }
    return Optional.empty();
  }

  private static boolean isBareScope(final String argument) {
    return "--initialize-at-build-time".equals(argument)
        || "--initialize-at-run-time".equals(argument);
  }

  private static boolean readTargetList(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext)
      throws IOException {
    if (values.isBlank()) {
      return NativeImageClassRootParsing.addWholeInventory(scanContext, roots);
    }
    final Set<String> targets =
        NativeImageClassRootParsing.parseClassNames(values, propertiesEntry);
    return NativeImageClassRootParsing.addTargets(targets, roots, scanContext);
  }

  private static boolean readClassInitialization(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext scanContext)
      throws IOException {
    if (values.isBlank()) {
      throw new IOException(
          "Malformed "
              + CLASS_INITIALIZATION_OPTION
              + " entry without a strategy in "
              + propertiesEntry.getName());
    }
    final Set<String> targets = new LinkedHashSet<>();
    boolean wholeInventory = false;
    for (final String value : values.split(",", -1)) {
      final ParsedInitializationTarget target = parseInitializationTarget(value, propertiesEntry);
      if (target.wholeInventory()) {
        wholeInventory = true;
      } else {
        targets.add(target.classOrPackage());
      }
    }
    if (wholeInventory) {
      NativeImageClassRootParsing.addWholeInventory(scanContext, roots);
    }
    return NativeImageClassRootParsing.addTargets(targets, roots, scanContext) || wholeInventory;
  }

  private static ParsedInitializationTarget parseInitializationTarget(
      final String value, final JarEntry propertiesEntry) throws IOException {
    final String item = value.trim();
    final int separator = item.lastIndexOf(':');
    if (separator < 0 || item.indexOf(':') != separator) {
      throw new IOException(
          "Malformed -H:ClassInitialization entry in " + propertiesEntry.getName());
    }
    final String strategy = item.substring(separator + 1).trim();
    if (!STRATEGIES.contains(strategy)) {
      throw new IOException(
          "Invalid " + CLASS_INITIALIZATION_OPTION + " strategy in " + propertiesEntry.getName());
    }
    final String target = item.substring(0, separator).trim();
    if (target.isEmpty()) {
      return new ParsedInitializationTarget("", true);
    }
    if (!NativeImageDynamicRoots.isBinaryClassName(target)) {
      throw new IOException(
          "Unsupported native-image class name in " + propertiesEntry.getName() + ": " + target);
    }
    return new ParsedInitializationTarget(target, false);
  }

  private record ParsedInitializationTarget(String classOrPackage, boolean wholeInventory) {}
}
