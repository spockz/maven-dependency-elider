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
  private final Map<Path, NativeImageArchiveInventory> archivesByPath;

  /** Lists every classpath archive containing each exact resource path. */
  private final Map<String, List<NativeImageArchiveInventory>> resourcesByPath;

  /** Combines logical classes so package selectors cross archive boundaries. */
  private final Set<String> allLogicalClasses;

  /** Carries Maven's invocation directory for later external configuration pointers. */
  private final Optional<Path> invocationBase;

  private NativeImageScanContext(
      final List<NativeImageArchiveInventory> archives, final Path invocationBase) {
    final Map<Path, NativeImageArchiveInventory> byPath = new ConcurrentHashMap<>();
    final Map<String, List<NativeImageArchiveInventory>> byResource = new ConcurrentHashMap<>();
    for (final NativeImageArchiveInventory archive : archives) {
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
    final Set<String> classes = new java.util.TreeSet<>();
    archives.forEach(archive -> classes.addAll(archive.logicalClasses()));
    this.allLogicalClasses = java.util.Collections.unmodifiableSet(classes);
    this.invocationBase = Optional.ofNullable(invocationBase);
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
    final List<NativeImageArchiveInventory> inventories = new ArrayList<>();
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
  /* package */
  Set<String> logicalClasses(final Optional<Path> archive) throws IOException {
    if (archive.isEmpty()) {
      return allLogicalClasses;
    }
    final NativeImageArchiveInventory inventory =
        archivesByPath.get(archive.orElseThrow().toRealPath());
    return inventory == null ? Set.of() : inventory.logicalClasses();
  }

  /* package */
  Optional<Path> invocationBaseDirectory() {
    return invocationBase;
  }

  /* package */
  Map<String, List<NativeImageArchiveInventory>> resourceIndex() {
    return resourcesByPath;
  }

  /* package */
  boolean readClasspathResource(
      final String resourcePath,
      final NativeImageDescriptorKind kind,
      final DescriptorReader reader,
      final Set<Path> providers)
      throws IOException {
    final List<NativeImageArchiveInventory> candidates = resourcesByPath.get(resourcePath);
    if (candidates == null) {
      return false;
    }
    boolean found = false;
    for (final NativeImageArchiveInventory candidate : candidates) {
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
        final Path provider = Path.of(archive.getName()).toRealPath();
        if (!archivesByPath.containsKey(provider)) {
          throw new IOException(
              "Native-image archive is outside the invocation inventory: " + provider);
        }
        providers.add(provider);
        NativeImageInput.archiveEntry(archive, entry, kind)
            .readDescriptor(reader, resourcePath, provider);
      }
    }
    return found;
  }

  private static NativeImageArchiveInventory inventory(final Path path) throws IOException {
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
    return new NativeImageArchiveInventory(path, logicalClasses, Map.copyOf(resources));
  }

  private static void addResourceProvider(
      final Map<String, List<NativeImageArchiveInventory>> byResource,
      final String resource,
      final NativeImageArchiveInventory archive) {
    byResource.computeIfAbsent(resource, ignored -> new ArrayList<>()).add(archive);
  }

  private static boolean readClasspathArchiveResource(
      final NativeImageArchiveInventory candidate,
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
          NativeImageInput.archiveEntry(archive, entry, kind)
              .readDescriptor(reader, resourcePath, candidate.path());
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
}
