/* WHY: Keeps archive inventory and archive-backed resource reads out of scan orchestration. */

package io.github.spockz.elider.plugin.nativeimage;

import io.github.spockz.elider.model.MultiReleaseClassInventory;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Builds archive inventories and reads one indexed classpath resource. */
/* package */ final class NativeImageArchiveCatalog {
  private NativeImageArchiveCatalog() {
    throw new AssertionError("static archive catalog");
  }

  /* package */
  static NativeImageArchiveInventory inventory(final Path path) throws IOException {
    final Set<String> logicalClasses = new TreeSet<>();
    final Set<String> resources = new HashSet<>();
    final Set<String> duplicateResources = new HashSet<>();
    try (JarFile archive = new JarFile(path.toFile())) {
      for (final JarEntry entry : java.util.Collections.list(archive.entries())) {
        final String entryName = entry.getName();
        if (!resources.add(entryName)) {
          duplicateResources.add(entryName);
        }
        if (!entry.isDirectory() && entryName.endsWith(".class")) {
          final String logicalName = MultiReleaseClassInventory.logicalClassName(entryName);
          if (!MultiReleaseClassInventory.isModuleDescriptor(logicalName)) {
            logicalClasses.add(MultiReleaseClassInventory.toBinaryClassName(logicalName));
          }
        }
      }
    }
    return new NativeImageArchiveInventory(
        path, Set.copyOf(logicalClasses), Set.copyOf(resources), Set.copyOf(duplicateResources));
  }

  /* package */
  static boolean readClasspathResource(
      final NativeImageArchiveInventory candidate,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final NativeImageScanContext.DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    try (JarFile archive = new JarFile(candidate.path().toFile())) {
      return readArchiveResource(
          archive,
          candidate.path(),
          candidate.duplicateResources().contains(resourcePath),
          resourcePath,
          kind,
          reader,
          providers);
    }
  }

  /* package */
  static boolean readArchiveResource(
      final JarFile archive,
      final Path archivePath,
      final boolean duplicateResource,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final NativeImageScanContext.DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    if (duplicateResource) {
      boolean found = false;
      try (java.util.zip.ZipInputStream stream =
          new java.util.zip.ZipInputStream(java.nio.file.Files.newInputStream(archivePath))) {
        java.util.zip.ZipEntry entry = stream.getNextEntry();
        while (entry != null) {
          if (!entry.isDirectory() && resourcePath.equals(entry.getName())) {
            providers.add(archivePath);
            NativeImageInput.archiveBytes(archive, resourcePath, kind, stream.readAllBytes())
                .readDescriptor(reader, resourcePath, archivePath);
            found = true;
          }
          entry = stream.getNextEntry();
        }
      }
      return found;
    }
    final JarEntry entry = archive.getJarEntry(resourcePath);
    if (entry == null || entry.isDirectory()) {
      return false;
    }
    readEntry(archive, archivePath, entry, resourcePath, kind, reader, providers);
    return true;
  }

  /* package */ static boolean matchesResource(final JarEntry entry, final String resourcePath) {
    return !entry.isDirectory() && resourcePath.equals(entry.getName());
  }

  private static void readEntry(
      final JarFile archive,
      final Path archivePath,
      final JarEntry entry,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final NativeImageScanContext.DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    providers.add(archivePath);
    NativeImageInput.archiveEntry(archive, entry, kind)
        .readDescriptor(reader, resourcePath, archivePath);
  }
}
