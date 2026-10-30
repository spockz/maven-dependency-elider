/* WHY: Resolves native-image classpath resources across the complete invocation archive set. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Holds invocation resources and logical classes in deterministic archive order. */
final class NativeImageScanContext {
  /** Resolves paths back to the indexed archive metadata. */
  private final Map<Path, ArchiveInventory> archivesByPath;

  /** Lists every classpath archive containing each exact resource path. */
  private final Map<String, List<ArchiveInventory>> resourcesByPath;

  /** Carries Maven's invocation directory for later external configuration pointers. */
  private final Optional<Path> invocationBaseDirectory;

  private NativeImageScanContext(final List<ArchiveInventory> archives, final Path invocationBase) {
    final Map<Path, ArchiveInventory> byPath = new ConcurrentHashMap<>();
    final Map<String, List<ArchiveInventory>> byResource = new ConcurrentHashMap<>();
    for (final ArchiveInventory archive : archives) {
      byPath.put(archive.path(), archive);
      for (final String resource : archive.resources().keySet()) {
        addResourceProvider(byResource, resource, archive);
      }
    }
    this.archivesByPath = java.util.Collections.unmodifiableMap(byPath);
    this.resourcesByPath =
        byResource.entrySet().stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    Map.Entry::getKey, entry -> List.copyOf(entry.getValue())));
    this.invocationBaseDirectory = Optional.ofNullable(invocationBase);
  }

  /* package */
  static NativeImageScanContext create(
      final List<ArtifactFileRef> candidates, final Path invocationBase) throws IOException {
    final List<ArtifactFileRef> ordered =
        candidates.stream()
            .sorted(
                Comparator.comparing(ArtifactFileRef::coordinate)
                    .thenComparing(
                        candidate -> candidate.filePath().toAbsolutePath().normalize().toString()))
            .toList();
    final Set<Path> indexedPaths = ConcurrentHashMap.newKeySet();
    final List<ArchiveInventory> inventories = new ArrayList<>();
    for (final ArtifactFileRef candidate : ordered) {
      final Path realPath = candidate.filePath().toRealPath();
      if (indexedPaths.add(realPath)) {
        inventories.add(inventory(realPath));
      }
    }
    final Path normalizedBase =
        invocationBase == null ? null : invocationBase.toAbsolutePath().normalize();
    return new NativeImageScanContext(inventories, normalizedBase);
  }

  /* package */
  static NativeImageScanContext singleArchive(final Path archive) throws IOException {
    final Path realPath = archive.toRealPath();
    return new NativeImageScanContext(List.of(inventory(realPath)), null);
  }

  /* package */
  Optional<Path> invocationBase() {
    return invocationBaseDirectory;
  }

  /* package */
  Set<String> logicalClasses(final Path archive) throws IOException {
    final ArchiveInventory inventory = archivesByPath.get(archive.toRealPath());
    return inventory == null ? Set.of() : inventory.logicalClasses();
  }

  /* package */
  Path archiveIdentity(final Path archive) throws IOException {
    final Path realPath = archive.toRealPath();
    if (!archivesByPath.containsKey(realPath)) {
      throw new IOException("Native-image archive is outside the invocation inventory: " + archive);
    }
    return realPath;
  }

  /* package */
  boolean readClasspathResource(
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    final List<ArchiveInventory> candidates = resourcesByPath.get(resourcePath);
    if (candidates == null) {
      return false;
    }
    boolean found = false;
    for (final ArchiveInventory candidate : candidates) {
      found |= readClasspathArchiveResource(candidate, resourcePath, kind, reader, providers);
    }
    return found;
  }

  /* package */
  boolean readDescriptorRelativeResource(
      final JarFile archive,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    boolean found = false;
    final Enumeration<JarEntry> entries = archive.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
      if (!entry.isDirectory() && resourcePath.equals(entry.getName())) {
        found = true;
        providers.add(archiveIdentity(Path.of(archive.getName())));
        reader.read(NativeImageInput.archiveEntry(archive, entry, kind));
      }
    }
    return found;
  }

  private static ArchiveInventory inventory(final Path path) throws IOException {
    final Set<String> logicalClasses = MultiReleaseClassInventory.logicalClassNames(path);
    final Map<String, Integer> resources = new ConcurrentHashMap<>();
    try (JarFile archive = new JarFile(path.toFile())) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (entry.isDirectory()) {
          continue;
        }
        final String name = entry.getName();
        resources.merge(name, 1, Integer::sum);
      }
    }
    return new ArchiveInventory(path, logicalClasses, Map.copyOf(resources));
  }

  private static void addResourceProvider(
      final Map<String, List<ArchiveInventory>> byResource,
      final String resource,
      final ArchiveInventory archive) {
    byResource.computeIfAbsent(resource, ignored -> new ArrayList<>()).add(archive);
  }

  private static boolean readClasspathArchiveResource(
      final ArchiveInventory candidate,
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final DescriptorReader reader,
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
          reader.read(NativeImageInput.archiveEntry(archive, entry, kind));
        }
      }
    }
    return found;
  }

  /* package */
  /** Keeps descriptor parsing independent of the archive or filesystem source. */
  @FunctionalInterface
  interface DescriptorReader {
    /* package */
    /** Reads one descriptor while preserving the parser's source-specific diagnostics. */
    void read(NativeImageInput input) throws IOException;
  }

  /** Metadata used to resolve resources and logical classes for one archive. */
  private record ArchiveInventory(
      Path path, Set<String> logicalClasses, Map<String, Integer> resources) {}
}
