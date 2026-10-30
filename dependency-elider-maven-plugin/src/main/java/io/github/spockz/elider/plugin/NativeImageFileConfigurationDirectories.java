/* WHY: Resolves bounded invocation-local config directories and snapshots their membership. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;

/** Reads recognized direct-child descriptors from invocation-local directories. */
/* package */ final class NativeImageFileConfigurationDirectories {
  private NativeImageFileConfigurationDirectories() {}

  /* package */ static boolean read(
      final String values,
      final JarEntry propertiesEntry,
      final Set<String> roots,
      final NativeImageScanContext context,
      final Set<NativeImageConsumedInput> consumedInputs)
      throws IOException {
    final Path invocationBase = invocationBase(context, propertiesEntry);
    final Set<Path> visitedDirectories = new HashSet<>();
    final Set<Path> snapshottedDirectories = new HashSet<>();
    final Set<Path> visitedDescriptors = new HashSet<>();
    boolean foundRoots = false;
    for (final String reference :
        NativeImageConfigurationDirectorySupport.references(values, propertiesEntry)) {
      final Path directory = resolveDirectory(reference, invocationBase, propertiesEntry);
      final Path canonicalDirectory = directory.toRealPath();
      final List<String> members =
          NativeImageConfigurationDirectorySupport.membershipEntries(directory);
      if (snapshottedDirectories.add(directory.toAbsolutePath().normalize())) {
        consumedInputs.add(NativeImageConsumedInput.directoryMembership(directory, members));
      }
      if (visitedDirectories.add(canonicalDirectory)) {
        for (final Path descriptor : descriptorFiles(directory, members)) {
          if (!visitedDescriptors.add(descriptor.toRealPath())) {
            continue;
          }
          final NativeImageDescriptorKind kind =
              NativeImageConfigurationDirectorySupport.kindFor(
                  java.util.Objects.requireNonNull(descriptor.getFileName()).toString());
          final int priorRoots = roots.size();
          NativeImageConfigurationPointers.readTypedDescriptor(
              NativeImageInput.file(descriptor, kind), kind, roots, consumedInputs);
          foundRoots |= roots.size() > priorRoots;
        }
      }
    }
    return foundRoots;
  }

  private static Path invocationBase(
      final NativeImageScanContext context, final JarEntry propertiesEntry) throws IOException {
    return context
        .invocationBaseDirectory()
        .orElseThrow(
            () ->
                new IOException(
                    "Native-image configuration directories require an invocation base: "
                        + propertiesEntry.getName()));
  }

  private static Path resolveDirectory(
      final String reference, final Path invocationBase, final JarEntry propertiesEntry)
      throws IOException {
    final Path requested = requestedPath(reference);
    final Path directory =
        requested.isAbsolute()
            ? requested.normalize()
            : invocationBase.resolve(requested).normalize();
    if (!Files.isDirectory(directory)) {
      throw new IOException(
          "Native-image configuration directory is missing in "
              + propertiesEntry.getName()
              + ": "
              + directory);
    }
    if (!requested.isAbsolute()) {
      validateRelativeBoundary(reference, directory, invocationBase);
    }
    return directory;
  }

  private static Path requestedPath(final String reference) throws IOException {
    try {
      return Path.of(reference);
    } catch (final java.nio.file.InvalidPathException exception) {
      throw new IOException(
          "Invalid native-image configuration directory: " + reference, exception);
    }
  }

  private static void validateRelativeBoundary(
      final String reference, final Path directory, final Path invocationBase) throws IOException {
    final Path canonicalBase = invocationBase.toRealPath();
    final Path canonicalDirectory = directory.toRealPath();
    if (!directory.startsWith(invocationBase) || !canonicalDirectory.startsWith(canonicalBase)) {
      throw new IOException(
          "Native-image configuration directory escapes invocation base: " + reference);
    }
  }

  private static List<Path> descriptorFiles(final Path directory, final List<String> members) {
    return members.stream()
        .map(member -> member.substring(0, member.indexOf('\u0000')))
        .sorted()
        .map(directory::resolve)
        .toList();
  }
}
