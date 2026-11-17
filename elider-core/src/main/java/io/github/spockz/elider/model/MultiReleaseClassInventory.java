/* WHY: Reads logical class inventory and release breakpoints independently
 * from projection writing. */

package io.github.spockz.elider.model;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads validated versioned class entries and their logical class names. */
public final class MultiReleaseClassInventory {
  /** Prefix separating versioned entries from base entries in an MRJAR. */
  private static final String VERSIONS_PREFIX = "META-INF/versions/";

  /** Suffix identifying class file payloads in archive entry names. */
  private static final String CLASS_SUFFIX = ".class";

  /** Logical class name of module descriptors ignored by classpath analysis. */
  private static final String MODULE_INFO_CLASS = "module-info" + CLASS_SUFFIX;

  /** Prevents construction of the static archive inventory helper. */
  private MultiReleaseClassInventory() {}

  /** Multi-release class inventory snapshot of an archive. */
  public record Snapshot(
      Set<String> logicalClassNames,
      List<Entry> versionedEntries,
      boolean hasRootModuleDescriptor) {
    /** Defensively copies the class-name set and versioned-entry list. */
    public Snapshot {
      logicalClassNames = Set.copyOf(logicalClassNames);
      versionedEntries = List.copyOf(versionedEntries);
    }

    /** Returns whether the archive contains versioned non-module-descriptor classes. */
    public boolean hasUnsupportedVersionedClasses() {
      return versionedEntries.stream().anyMatch(entry -> !isModuleDescriptor(entry.logicalName()));
    }

    /** Returns the sorted release versions that contain versioned classes. */
    public List<Integer> versionedClassReleases() {
      final Set<Integer> releases = new TreeSet<>();
      for (final Entry entry : versionedEntries) {
        if (!isModuleDescriptor(entry.logicalName())) {
          releases.add(entry.release());
        }
      }
      return List.copyOf(releases);
    }

    /** Returns binary names of versioned classes above {@code release}. */
    public Set<String> classNamesAboveRelease(final int release) {
      final Set<String> classNames = new TreeSet<>();
      for (final Entry entry : versionedEntries) {
        if (entry.release() > release && !isModuleDescriptor(entry.logicalName())) {
          classNames.add(toBinaryClassName(entry.logicalName()));
        }
      }
      return Set.copyOf(classNames);
    }
  }

  /** Converts a `.class` archive entry name into a binary class name. */
  public static String toBinaryClassName(final String logicalName) {
    return logicalName.substring(0, logicalName.length() - CLASS_SUFFIX.length()).replace('/', '.');
  }

  /** Inspects a JAR archive and returns its multi-release class inventory snapshot. */
  public static Snapshot inspect(final Path archivePath) throws IOException {
    final Set<String> logicalClassNames = new TreeSet<>();
    final List<Entry> versionedEntries = new ArrayList<>();
    boolean hasRootModuleDescriptor = false;
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      for (final JarEntry entry : archive.stream().toList()) {
        if (entry.isDirectory()) {
          continue;
        }
        final String name = entry.getName();
        if (MODULE_INFO_CLASS.equals(name)) {
          hasRootModuleDescriptor = true;
        }
        if (!name.endsWith(CLASS_SUFFIX)) {
          continue;
        }
        final String logicalName;
        if (name.startsWith(VERSIONS_PREFIX)) {
          final Entry parsed = parse(name);
          versionedEntries.add(parsed);
          logicalName = parsed.logicalName();
        } else {
          logicalName = name;
        }
        if (!isModuleDescriptor(logicalName)) {
          logicalClassNames.add(toBinaryClassName(logicalName));
        }
      }
    }
    return new Snapshot(
        Set.copyOf(logicalClassNames), List.copyOf(versionedEntries), hasRootModuleDescriptor);
  }

  /** Returns whether the archive contains versioned non-module-descriptor classes. */
  public static boolean hasUnsupportedVersionedClasses(final Path archivePath) throws IOException {
    return read(archivePath).stream().anyMatch(entry -> !isModuleDescriptor(entry.logicalName()));
  }

  /** Returns all binary logical class names present in the archive. */
  public static Set<String> logicalClassNames(final Path archivePath) throws IOException {
    final Set<String> classNames = new TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      for (final JarEntry entry : archive.stream().toList()) {
        if (entry.isDirectory() || !entry.getName().endsWith(CLASS_SUFFIX)) {
          continue;
        }
        final String logicalName = logicalClassName(entry.getName());
        if (!isModuleDescriptor(logicalName)) {
          classNames.add(toBinaryClassName(logicalName));
        }
      }
    }
    return Set.copyOf(classNames);
  }

  /** Returns the base logical class name for a possibly versioned archive entry. */
  public static String logicalClassName(final String entryName) throws IOException {
    if (!entryName.startsWith(VERSIONS_PREFIX)) {
      return entryName;
    }
    return parse(entryName).logicalName();
  }

  /** Returns whether the logical entry name refers to a {@code module-info.class}. */
  public static boolean isModuleDescriptor(final String logicalName) {
    return MODULE_INFO_CLASS.equals(logicalName) || logicalName.endsWith("/" + MODULE_INFO_CLASS);
  }

  private static List<Entry> read(final Path archivePath) throws IOException {
    final List<Entry> entries = new ArrayList<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      for (final JarEntry entry : archive.stream().toList()) {
        final String name = entry.getName();
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
    final MultiReleaseEntryPath parsed = MultiReleaseEntryPath.parse(entryName, false);
    if (parsed == null || parsed.logicalName().isBlank()) {
      throw new IOException("Empty multi-release class name " + entryName);
    }
    return new Entry(parsed.release(), parsed.logicalName());
  }

  /** Parsed versioned class entry under {@code META-INF/versions/}. */
  public record Entry(int release, String logicalName) {}
}
