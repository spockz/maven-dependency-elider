/* WHY: Keeps archive inventory and archive-backed resource reads out of scan orchestration. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Enumeration;
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
    try (JarFile archive = new JarFile(path.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        final String entryName = entry.getName();
        resources.add(entryName);
        if (!entry.isDirectory() && entryName.endsWith(".class")) {
          final String logicalName = MultiReleaseClassInventory.logicalClassName(entryName);
          if (!MultiReleaseClassInventory.isModuleDescriptor(logicalName)) {
            logicalClasses.add(
                logicalName
                    .substring(0, logicalName.length() - ".class".length())
                    .replace('/', '.'));
          }
        }
      }
    }
    return new NativeImageArchiveInventory(path, Set.copyOf(logicalClasses), Set.copyOf(resources));
  }

  /* package */
  static boolean readClasspathResource(
      final NativeImageArchiveInventory candidate,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final NativeImageScanContext.DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    boolean found = false;
    try (JarFile archive = new JarFile(candidate.path().toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (!entry.isDirectory() && resourcePath.equals(entry.getName())) {
          found = true;
          providers.add(candidate.path());
          NativeImageInput.archiveEntry(archive, entry, kind)
              .readDescriptor(reader, resourcePath, candidate.path());
        }
      }
    }
    return found;
  }
}
