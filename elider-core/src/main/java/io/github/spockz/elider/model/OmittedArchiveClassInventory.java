/* WHY: Isolates physical archive enumeration from the proof policy. */

package io.github.spockz.elider.model;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Reads logical class names while rejecting repeated physical archive paths. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class OmittedArchiveClassInventory {
  private OmittedArchiveClassInventory() {}

  static Set<String> read(final Path path) throws IOException {
    final Set<String> logicalNames = new HashSet<>();
    final Set<String> physicalEntryNames = new HashSet<>();
    try (ZipFile zip = new ZipFile(path.toFile())) {
      final Enumeration<? extends ZipEntry> entries = zip.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        if (!physicalEntryNames.add(entry.getName())) {
          throw new IOException("Duplicate physical archive entry: " + entry.getName());
        }
        final String name = className(entry);
        if (name != null) {
          logicalNames.add(name);
        }
      }
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable archive: " + path, exception);
    }
    return logicalNames;
  }

  private static String className(final ZipEntry entry) throws IOException {
    final String entryName = entry.getName();
    if (entry.isDirectory() || !entryName.endsWith(".class")) {
      return null;
    }
    String name = entryName.substring(0, entryName.length() - ".class".length());
    if (name.startsWith("META-INF/versions/")) {
      final int slash = name.indexOf('/', "META-INF/versions/".length());
      if (slash < 0) {
        throw new IOException("Malformed multi-release class entry: " + entryName);
      }
      name = name.substring(slash + 1);
    }
    if ("module-info".equals(name) || name.endsWith("/module-info")) {
      return null;
    }
    return name;
  }
}
