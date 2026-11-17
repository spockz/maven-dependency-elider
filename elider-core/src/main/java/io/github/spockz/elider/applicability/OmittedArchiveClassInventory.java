/* WHY: Isolates physical archive enumeration from the proof policy. */

package io.github.spockz.elider.applicability;

import io.github.spockz.elider.model.MultiReleaseEntryPath;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Reads logical class names while rejecting repeated physical archive paths. */
public final class OmittedArchiveClassInventory {
  private OmittedArchiveClassInventory() {}

  /** Reads the complete physical class-entry inventory from one regular archive. */
  public static Set<String> read(final Path path) throws IOException {
    final Set<String> logicalNames = new HashSet<>();
    final Set<String> physicalEntryNames = new HashSet<>();
    try (ZipFile zip = new ZipFile(path.toFile())) {
      for (final ZipEntry entry : zip.stream().toList()) {
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
    final String physicalClassName = entryName.substring(0, entryName.length() - ".class".length());
    final String name =
        entryName.startsWith(MultiReleaseEntryPath.PREFIX)
            ? MultiReleaseEntryPath.parse(physicalClassName, false).logicalName()
            : physicalClassName;
    if (name.isEmpty() || name.startsWith("/")) {
      throw new IOException("Malformed class entry with empty logical name: " + entryName);
    }
    if ("module-info".equals(name) || name.endsWith("/module-info")) {
      return null;
    }
    return name;
  }
}
