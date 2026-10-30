/* WHY: Models link-at-build-time classes only from the indexed invocation archive set. */

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.regex.Pattern;

/** Reads the bounded class and indexed-archive forms of LinkAtBuildTime options. */
/* package */ final class NativeImageLinkAtBuildTimeRoots {
  /** Exact value prefixes audited for type-name target lists. */
  private static final String[] CLASS_OPTIONS = {"-H:LinkAtBuildTime=", "--link-at-build-time="};

  /** Exact value prefixes audited for indexed archive paths. */
  private static final String[] PATH_OPTIONS = {
    "-H:LinkAtBuildTimePaths=", "--link-at-build-time-paths="
  };

  private NativeImageLinkAtBuildTimeRoots() {}

  /* package */ static Optional<Boolean> read(
      final String argument,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    if (isBareClassOption(argument)) {
      return Optional.of(NativeImageClassRootParsing.addWholeInventory(context, roots));
    }
    for (final String prefix : CLASS_OPTIONS) {
      if (argument.startsWith(prefix)) {
        final Set<String> targets =
            NativeImageClassRootParsing.parseClassNames(
                argument.substring(prefix.length()), propertiesEntry);
        return Optional.of(NativeImageClassRootParsing.addTargets(targets, roots, context, true));
      }
    }
    for (final String prefix : PATH_OPTIONS) {
      if (argument.startsWith(prefix)) {
        return Optional.of(
            addIndexedPathClasses(
                argument.substring(prefix.length()),
                propertiesEntry,
                roots,
                context,
                consumedInputs));
      }
    }
    if (isBarePathOption(argument)) {
      throw missingValue(argument, propertiesEntry);
    }
    return Optional.empty();
  }

  private static boolean addIndexedPathClasses(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    if (values.isBlank()) {
      throw malformedPathList(propertiesEntry, values);
    }
    final Path invocationBase =
        context
            .invocationBaseDirectory()
            .orElseThrow(
                () ->
                    new IOException(
                        "Native-image link-at-build-time paths require an invocation base: "
                            + propertiesEntry.getName()));
    final Set<Path> visited = new LinkedHashSet<>();
    boolean foundClasses = false;
    for (final String rawPath : values.split(Pattern.quote(File.pathSeparator), -1)) {
      final String value = rawPath.trim();
      if (value.isEmpty()) {
        throw malformedPathList(propertiesEntry, values);
      }
      final Path logicalPath = resolveIndexedPath(value, propertiesEntry, invocationBase);
      final NativeImageConsumedInput pathReference =
          NativeImageConsumedInput.archiveReference(logicalPath);
      if (isModulePath(pathReference.canonicalPath())) {
        throw unsupportedModulePath(value);
      }
      consumedInputs.add(pathReference);
      final Path canonical = pathReference.canonicalPath();
      if (visited.add(canonical)) {
        final Set<String> classes = context.indexedArchiveClasses(canonical);
        roots.addAll(classes);
        foundClasses |= !classes.isEmpty();
      }
    }
    return foundClasses;
  }

  private static Path resolveIndexedPath(
      final String value, final JarEntry propertiesEntry, final Path invocationBase)
      throws IOException {
    final Path requested = path(value, propertiesEntry);
    final Path resolved =
        requested.isAbsolute()
            ? requested.normalize()
            : invocationBase.resolve(requested).normalize();
    if (isModulePath(resolved)) {
      throw unsupportedModulePath(value);
    }
    if (!Files.exists(resolved)) {
      throw new IOException("Native-image link-at-build-time path is missing: " + value);
    }
    return resolved;
  }

  private static boolean isModulePath(final Path path) {
    final Path fileName = path.getFileName();
    return fileName != null
        && fileName.toString().toLowerCase(java.util.Locale.ROOT).endsWith(".jmod");
  }

  private static IOException unsupportedModulePath(final String value) {
    return new IOException(
        "Native-image link-at-build-time module paths are unsupported: " + value);
  }

  private static Path path(final String value, final JarEntry propertiesEntry) throws IOException {
    try {
      return Path.of(value);
    } catch (final java.nio.file.InvalidPathException exception) {
      throw new IOException(
          "Invalid native-image link-at-build-time path in "
              + propertiesEntry.getName()
              + ": "
              + value,
          exception);
    }
  }

  private static boolean isBareClassOption(final String argument) {
    return "-H:LinkAtBuildTime".equals(argument) || "--link-at-build-time".equals(argument);
  }

  private static boolean isBarePathOption(final String argument) {
    return "-H:LinkAtBuildTimePaths".equals(argument)
        || "--link-at-build-time-paths".equals(argument);
  }

  private static IOException missingValue(final String argument, final JarEntry propertiesEntry) {
    return new IOException(
        "Native-image link-at-build-time path option has no value in "
            + propertiesEntry.getName()
            + ": "
            + argument);
  }

  private static IOException malformedPathList(
      final JarEntry propertiesEntry, final String values) {
    return new IOException(
        "Malformed native-image link-at-build-time path list in "
            + propertiesEntry.getName()
            + ": "
            + values);
  }
}
