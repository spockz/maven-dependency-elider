/* WHY: Reads logical class inventory and release breakpoints independently
 * from projection writing. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads validated versioned class entries and their logical class names. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MultiReleaseClassInventory {
  /** Prefix separating versioned entries from base entries in an MRJAR. */
  private static final String VERSIONS_PREFIX = "META-INF/versions/";

  /** Suffix identifying class file payloads in archive entry names. */
  private static final String CLASS_SUFFIX = ".class";

  /** Logical class name of module descriptors ignored by classpath analysis. */
  private static final String MODULE_INFO_CLASS = "module-info" + CLASS_SUFFIX;

  /** Prevents construction of the static archive inventory helper. */
  private MultiReleaseClassInventory() {}

  static boolean hasUnsupportedVersionedClasses(final Path archivePath) throws IOException {
    return read(archivePath).stream().anyMatch(entry -> !isModuleDescriptor(entry.logicalName()));
  }

  static List<Integer> versionedClassReleases(final Path archivePath) throws IOException {
    final Set<Integer> releases = new TreeSet<>();
    for (final Entry entry : read(archivePath)) {
      if (!isModuleDescriptor(entry.logicalName())) {
        releases.add(entry.release());
      }
    }
    return List.copyOf(releases);
  }

  static Set<String> classNamesAboveRelease(final Path archivePath, final int release)
      throws IOException {
    final Set<String> classNames = new TreeSet<>();
    for (final Entry entry : read(archivePath)) {
      if (entry.release() > release && !isModuleDescriptor(entry.logicalName())) {
        classNames.add(
            entry
                .logicalName()
                .substring(0, entry.logicalName().length() - CLASS_SUFFIX.length())
                .replace('/', '.'));
      }
    }
    return Set.copyOf(classNames);
  }

  static String logicalClassName(final String entryName) throws IOException {
    if (!entryName.startsWith(VERSIONS_PREFIX)) {
      return entryName;
    }
    return parse(entryName).logicalName();
  }

  static boolean isModuleDescriptor(final String logicalName) {
    return MODULE_INFO_CLASS.equals(logicalName) || logicalName.endsWith("/" + MODULE_INFO_CLASS);
  }

  private static List<Entry> read(final Path archivePath) throws IOException {
    final List<Entry> entries = new ArrayList<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final Enumeration<JarEntry> jarEntries = archive.entries();
      while (jarEntries.hasMoreElements()) {
        final String name = jarEntries.nextElement().getName();
        if (isVersionedClass(name)) {
          entries.add(parse(name));
        }
      }
    }
    return List.copyOf(entries);
  }

  private static boolean isVersionedClass(final String entryName) {
    return entryName.startsWith(VERSIONS_PREFIX) && entryName.endsWith(CLASS_SUFFIX);
  }

  private static Entry parse(final String entryName) throws IOException {
    final int versionEnd = entryName.indexOf('/', VERSIONS_PREFIX.length());
    if (versionEnd < 0 || versionEnd == entryName.length() - 1) {
      throw new IOException("Malformed multi-release class entry " + entryName);
    }
    final String versionText = entryName.substring(VERSIONS_PREFIX.length(), versionEnd);
    final int version = parseVersion(entryName, versionText);
    if (version < 9 || !Integer.toString(version).equals(versionText)) {
      throw new IOException("Noncanonical multi-release class tier " + entryName);
    }
    final String logicalName = entryName.substring(versionEnd + 1);
    if (logicalName.isBlank()) {
      throw new IOException("Empty multi-release class name " + entryName);
    }
    return new Entry(version, logicalName);
  }

  private static int parseVersion(final String entryName, final String versionText)
      throws IOException {
    try {
      return Integer.parseInt(versionText);
    } catch (final NumberFormatException exception) {
      throw new IOException("Malformed multi-release class tier " + entryName, exception);
    }
  }

  private record Entry(int release, String logicalName) {}
}
