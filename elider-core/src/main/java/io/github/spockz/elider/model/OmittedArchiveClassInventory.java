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
  /** First release number allowed in a multi-release directory. */
  private static final int MINIMUM_VERSIONED_RELEASE = 9;

  /** Prefix shared by all versioned class entries. */
  private static final String VERSIONED_PREFIX = "META-INF/versions/";

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
    final String physicalClassName = entryName.substring(0, entryName.length() - ".class".length());
    final String name =
        entryName.startsWith(VERSIONED_PREFIX)
            ? versionedClassName(entryName, physicalClassName)
            : physicalClassName;
    if (name.isEmpty() || name.startsWith("/")) {
      throw new IOException("Malformed class entry with empty logical name: " + entryName);
    }
    if ("module-info".equals(name) || name.endsWith("/module-info")) {
      return null;
    }
    return name;
  }

  private static String versionedClassName(final String entryName, final String physicalName)
      throws IOException {
    final int slash = physicalName.indexOf('/', VERSIONED_PREFIX.length());
    if (slash < 0) {
      throw malformedVersionedClass(entryName);
    }
    validateRelease(entryName.substring(VERSIONED_PREFIX.length(), slash), entryName);
    return physicalName.substring(slash + 1);
  }

  private static void validateRelease(final String release, final String entryName)
      throws IOException {
    if (!release.matches("[1-9][0-9]*")) {
      throw malformedVersionedClass(entryName);
    }
    final int releaseNumber;
    try {
      releaseNumber = Integer.parseInt(release);
    } catch (final NumberFormatException exception) {
      throw malformedVersionedClass(entryName, exception);
    }
    if (releaseNumber < MINIMUM_VERSIONED_RELEASE) {
      throw malformedVersionedClass(entryName);
    }
  }

  private static IOException malformedVersionedClass(final String entryName) {
    return new IOException("Malformed multi-release class entry: " + entryName);
  }

  private static IOException malformedVersionedClass(
      final String entryName, final NumberFormatException cause) {
    return new IOException("Malformed multi-release class entry: " + entryName, cause);
  }
}
