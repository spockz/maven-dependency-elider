/* WHY: Shares direct-child path rules between file and classpath descriptor directories. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Shared path and inventory operations for bounded configuration directories. */
/* package */ final class NativeImageConfigurationDirectorySupport {
  private NativeImageConfigurationDirectorySupport() {}

  /* package */ static List<String> membershipEntries(final Path directory) throws IOException {
    final Path canonicalDirectory = directory.toRealPath();
    final List<String> entries = new ArrayList<>();
    try (DirectoryStream<Path> children = Files.newDirectoryStream(directory)) {
      for (final Path child : children) {
        final Path fileName = child.getFileName();
        if (fileName == null) {
          throw new IOException("Native-image configuration child has no filename: " + child);
        }
        final NativeImageDescriptorKind kind = kindFor(fileName.toString());
        if (kind != null && Files.isRegularFile(child)) {
          final Path canonicalChild = child.toRealPath();
          if (!canonicalChild.startsWith(canonicalDirectory)) {
            throw new IOException(
                "Native-image configuration file escapes its directory: " + child);
          }
          entries.add(fileName + "\u0000" + kind.name() + "\u0000" + canonicalChild);
        }
      }
    }
    entries.sort(Comparator.naturalOrder());
    return List.copyOf(entries);
  }

  /* package */ static byte[] membershipBytes(final List<String> entries) {
    final StringBuilder value = new StringBuilder();
    for (final String entry : entries) {
      value.append(entry.length()).append(':').append(entry);
    }
    return value.toString().getBytes(StandardCharsets.UTF_8);
  }

  /* package */ static List<String> references(
      final String values, final java.util.jar.JarEntry propertiesEntry) throws IOException {
    if (values.isBlank()) {
      throw new IOException(
          "Native-image configuration directory option has no paths in "
              + propertiesEntry.getName());
    }
    final List<String> references =
        java.util.Arrays.stream(values.split(",", -1)).map(String::trim).toList();
    if (references.stream().anyMatch(String::isBlank)) {
      throw new IOException(
          "Native-image configuration directory option has an empty path in "
              + propertiesEntry.getName());
    }
    return references;
  }

  /* package */ static NativeImageDescriptorKind kindFor(final String name) {
    final NativeImageDescriptorKind classKind = NativeImageDescriptorKind.classConfigFor(name);
    if (classKind != null) {
      return classKind;
    }
    return NativeImageResourceConfig.isNativeImageResourceConfig(name)
        ? NativeImageDescriptorKind.RESOURCES
        : null;
  }
}
