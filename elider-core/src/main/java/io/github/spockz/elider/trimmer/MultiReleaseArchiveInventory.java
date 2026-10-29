/* WHY: Separates physical ZIP validation and indexing from immutable elevation-plan decisions. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipFile;

/** Reads and validates an archive's physical release-tier entries. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseArchiveInventory {
  private MultiReleaseArchiveInventory() {}

  static ArchiveIndex read(final java.nio.file.Path source) throws IOException {
    try (JarFile archive = new JarFile(source.toFile(), false, ZipFile.OPEN_READ)) {
      final ArchiveIndexBuilder builder = new ArchiveIndexBuilder(archive.getManifest());
      final java.util.Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        builder.add(archive, entries.nextElement());
      }
      return builder.build();
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Unreadable multi-release archive: " + source, exception);
    }
  }

  record ArchiveIndex(
      List<String> names,
      Map<String, MultiReleaseArchivePlan.ClassVariant> rootClasses,
      Map<String, NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant>> versionedClasses,
      Map<String, NavigableMap<Integer, String>> versionedResources,
      Set<String> versionedFiles,
      Manifest manifest) {}

  /* WHY: This builder is call-local. Linked maps preserve source traversal order. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static final class ArchiveIndexBuilder {
    private final List<String> names = new ArrayList<>();
    private final Map<String, MultiReleaseArchivePlan.ClassVariant> rootClasses =
        new LinkedHashMap<>();
    private final Map<String, NavigableMap<Integer, MultiReleaseArchivePlan.ClassVariant>>
        versionedClasses = new LinkedHashMap<>();
    private final Map<String, NavigableMap<Integer, String>> versionedResources =
        new LinkedHashMap<>();
    private final Set<String> versionedFiles = new HashSet<>();
    private final Set<String> seenNames = new HashSet<>();
    private final Manifest manifest;

    private ArchiveIndexBuilder(final Manifest manifest) {
      this.manifest = manifest;
    }

    private void add(final JarFile archive, final JarEntry entry) throws IOException {
      final String name = entry.getName();
      if (!seenNames.add(name)) {
        throw new IOException("Duplicate archive entry cannot be preserved safely: " + name);
      }
      names.add(name);
      if (entry.isDirectory() || !name.startsWith(MultiReleaseArchivePlan.VERSIONS_PREFIX)) {
        addRootClass(archive, entry, name);
      } else {
        addVersionedEntry(archive, entry, name);
      }
    }

    private void addRootClass(final JarFile archive, final JarEntry entry, final String name)
        throws IOException {
      if (entry.isDirectory() || !name.endsWith(MultiReleaseArchivePlan.CLASS_SUFFIX)) {
        return;
      }
      final MultiReleaseArchivePlan.ClassVariant variant =
          MultiReleaseClassFile.read(archive, entry, name, 0);
      if (MultiReleaseArchivePlan.MODULE_INFO.equals(variant.name())) {
        throw new IOException("Unsupported root module descriptor: " + name);
      }
      if (rootClasses.putIfAbsent(variant.name(), variant) != null) {
        throw new IOException("Duplicate root class: " + variant.name().replace('/', '.'));
      }
    }

    private void addVersionedEntry(final JarFile archive, final JarEntry entry, final String name)
        throws IOException {
      final MultiReleaseArchivePlan.VersionedPath path =
          MultiReleaseArchivePlan.parseVersionedPath(name, entry.isDirectory());
      if (path == null) {
        return;
      }
      rejectVersionedMetaInf(path, name);
      if (entry.isDirectory()) {
        return;
      }
      versionedFiles.add(name);
      if (name.endsWith(MultiReleaseArchivePlan.CLASS_SUFFIX)) {
        addVersionedClass(archive, entry, path);
      } else {
        versionedResources
            .computeIfAbsent(path.logicalName(), ignored -> new TreeMap<>())
            .put(path.release(), name);
      }
    }

    private static void rejectVersionedMetaInf(
        final MultiReleaseArchivePlan.VersionedPath path, final String name) throws IOException {
      if ("META-INF".equals(path.logicalName()) || path.logicalName().startsWith("META-INF/")) {
        throw new IOException("Versioned META-INF resources are not supported: " + name);
      }
    }

    private void addVersionedClass(
        final JarFile archive,
        final JarEntry entry,
        final MultiReleaseArchivePlan.VersionedPath path)
        throws IOException {
      final MultiReleaseArchivePlan.ClassVariant variant =
          MultiReleaseClassFile.read(archive, entry, path.logicalName(), path.release());
      if (!MultiReleaseArchivePlan.MODULE_INFO.equals(variant.name())) {
        versionedClasses
            .computeIfAbsent(variant.name(), ignored -> new TreeMap<>())
            .put(path.release(), variant);
      }
    }

    private ArchiveIndex build() {
      return new ArchiveIndex(
          List.copyOf(names),
          Map.copyOf(rootClasses),
          Map.copyOf(versionedClasses),
          Map.copyOf(versionedResources),
          Set.copyOf(versionedFiles),
          manifest);
    }
  }
}
