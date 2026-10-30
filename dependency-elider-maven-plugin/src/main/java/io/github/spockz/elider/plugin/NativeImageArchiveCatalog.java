/* WHY: Keeps archive inventory and archive-backed resource reads out of scan orchestration. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Builds archive inventories and reads one indexed classpath resource. */
/* package */ final class NativeImageArchiveCatalog {
  private NativeImageArchiveCatalog() {
    throw new AssertionError("static archive catalog");
  }

  /* package */
  static NativeImageArchiveInventory inventory(final Path path) throws IOException {
    final Set<String> logicalClasses = MultiReleaseClassInventory.logicalClassNames(path);
    final Map<String, Integer> resources = new ConcurrentHashMap<>();
    try (JarFile archive = new JarFile(path.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (!entry.isDirectory()) {
          resources.merge(entry.getName(), 1, Integer::sum);
        }
      }
    }
    return new NativeImageArchiveInventory(path, logicalClasses, Map.copyOf(resources));
  }

  /* package */
  static void addResourceProvider(
      final Map<String, List<NativeImageArchiveInventory>> byResource,
      final String resource,
      final NativeImageArchiveInventory archive) {
    byResource.computeIfAbsent(resource, ignored -> new ArrayList<>()).add(archive);
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
