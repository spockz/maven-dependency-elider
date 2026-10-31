/* WHY: Resolves native-image classpath resources across the complete invocation archive set. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
    this.archivesByPath =
        archives.stream()
            .collect(
                java.util.stream.Collectors.toUnmodifiableMap(
                    NativeImageArchiveInventory::path, archive -> archive));
    final Map<String, List<NativeImageArchiveInventory>> byResource =
        archives.stream()
            .flatMap(
                archive ->
                    archive.resources().stream().map(resource -> Map.entry(resource, archive)))
            .collect(
                java.util.stream.Collectors.groupingBy(
                    Map.Entry::getKey,
                    java.util.LinkedHashMap::new,
                    java.util.stream.Collectors.mapping(
                        Map.Entry::getValue, java.util.stream.Collectors.toList())));
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
    final Set<Path> indexedPaths = new HashSet<>();
    final List<NativeImageArchiveInventory> inventories = new ArrayList<>();
    for (final ArtifactFileRef candidate : ordered) {
      final Path realPath = candidate.filePath().toRealPath();
      if (indexedPaths.add(realPath)) {
        inventories.add(NativeImageArchiveCatalog.inventory(realPath));
      }
    }
    final Path normalizedBase =
        invocationBase == null ? null : invocationBase.toAbsolutePath().normalize();
    return new NativeImageScanContext(inventories, normalizedBase);
  }

  /* package */
  static NativeImageScanContext singleArchive(final Path archive) throws IOException {
    final Path realPath = archive.toRealPath();
    return new NativeImageScanContext(List.of(NativeImageArchiveCatalog.inventory(realPath)), null);
  }

  /* package */
  Set<String> logicalClasses(final Optional<Path> archive) throws IOException {
    if (archive.isEmpty()) {
      return allLogicalClasses;
    }
    final NativeImageArchiveInventory inventory =
        archivesByPath.get(archive.orElseThrow().toRealPath());
    return inventory == null ? Set.of() : inventory.logicalClasses();
  }

  /* package */ Set<String> indexedArchiveClasses(final Path archive) throws IOException {
    if (Files.isDirectory(archive)) {
      throw new IOException(
          "Native-image link-at-build-time directory paths are unsupported: " + archive);
    }
    if (!Files.isRegularFile(archive)) {
      throw new IOException("Native-image link-at-build-time path is missing: " + archive);
    }
    final Path realPath = archive.toRealPath();
    final NativeImageArchiveInventory inventory = archivesByPath.get(realPath);
    if (inventory == null) {
      throw new IOException(
          "Native-image link-at-build-time path does not match an indexed archive identity; "
              + "module paths are unsupported: "
              + archive);
    }
    return inventory.logicalClasses();
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
      found |=
          NativeImageArchiveCatalog.readClasspathResource(
              candidate, resourcePath, kind, reader, providers);
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

  /* package */
  /** Keeps descriptor parsing independent of the archive or filesystem source. */
  @FunctionalInterface
  interface DescriptorReader {
    /* package */
    /** Reads one descriptor while preserving the parser's source-specific diagnostics. */
    void read(NativeImageInput input) throws IOException;
  }
}
