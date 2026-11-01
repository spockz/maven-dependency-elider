// WHY: Retains successful claim-independent reproduction metadata only for one assessment.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OmittedArchiveClassInventory;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Stores successful live reproduction metadata until each candidate's final proof. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SourceReproductionInvocationCache {
  /** Reproductions are read by sequential assessment passes. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private final Map<ReproductionKey, PreparedReproduction> reproductions = new HashMap<>();

  /** Inventories are tied to candidate GAVCE, real path, and whole-file digest. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private final Map<PhysicalInventoryKey, Set<String>> physicalInventories = new HashMap<>();

  /** Keys indicate inventories first produced by the exact reproduction parse. */
  private final Set<PhysicalInventoryKey> reproducedInventories = new HashSet<>();

  /** Counts original archive parser invocations. */
  private long originalArchiveParses;

  /** Counts sources archive parser invocations. */
  private long sourceArchiveParses;

  /** Counts compiler tasks that reached JavacTask.parse. */
  private long compilerInvocations;

  /** Counts successful reproduction metadata cache hits. */
  private long reproductionCacheHits;

  /** Counts physical inventory parser invocations. */
  private long physicalInventoryParses;

  /** Counts physical inventory cache hits. */
  private long physicalInventoryCacheHits;

  /** Counts inventory hits that use the inventory from an exact reproduction. */
  private long physicalInventoryReusesFromReproduction;

  /** Assessment ownership keeps these maps sequential and invocation-local. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  SourceReproductionInvocationCache() {}

  Optional<PreparedReproduction> reproduction(final ReproductionKey key) {
    return Optional.ofNullable(reproductions.get(key));
  }

  void recordReproductionHit() {
    reproductionCacheHits++;
  }

  void archiveParsed(final boolean sources) {
    if (sources) {
      sourceArchiveParses++;
    } else {
      originalArchiveParses++;
    }
  }

  void compilerTaskStarted() {
    compilerInvocations++;
  }

  void cacheReproduction(
      final ReproductionKey key,
      final PreparedReproduction prepared,
      final ArtifactCoordinate candidate,
      final Path originalPath,
      final String originalSha256)
      throws IOException {
    reproductions.put(key, prepared);
    final PhysicalInventoryKey inventoryKey =
        new PhysicalInventoryKey(candidate.toId(), originalPath.toRealPath(), originalSha256);
    final Set<String> originalClassNames =
        prepared.originalClasses().stream()
            .map(SourceReproductionInvocationCache::logicalClassName)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    physicalInventories.put(inventoryKey, originalClassNames);
    reproducedInventories.add(inventoryKey);
  }

  Set<String> readPhysicalClassInventory(
      final ArtifactCoordinate coordinate, final Path path, final String expectedSha256)
      throws IOException {
    final Path realPath = path.toRealPath();
    final String currentSha256 = SourceFileDigest.sha256(realPath);
    if (!currentSha256.equals(expectedSha256)) {
      throw new IOException("Artifact digest no longer matches the expected inventory bytes");
    }
    final PhysicalInventoryKey key =
        new PhysicalInventoryKey(coordinate.toId(), realPath, currentSha256);
    final Set<String> cached = physicalInventories.get(key);
    if (cached != null) {
      physicalInventoryCacheHits++;
      if (reproducedInventories.contains(key)) {
        physicalInventoryReusesFromReproduction++;
      }
      requireStableFile(realPath, currentSha256);
      return cached;
    }
    physicalInventoryParses++;
    final Set<String> inventory = OmittedArchiveClassInventory.read(realPath);
    requireStableFile(realPath, currentSha256);
    final Set<String> immutable = Set.copyOf(inventory);
    physicalInventories.put(key, immutable);
    return immutable;
  }

  void releaseCandidates(final Collection<ArtifactCoordinate> candidates) {
    final Set<String> candidateIds =
        candidates.stream()
            .map(ArtifactCoordinate::toId)
            .collect(java.util.stream.Collectors.toSet());
    reproductions.keySet().removeIf(key -> candidateIds.contains(key.candidateId()));
    physicalInventories.keySet().removeIf(key -> candidateIds.contains(key.coordinateId()));
    reproducedInventories.removeIf(key -> candidateIds.contains(key.coordinateId()));
  }

  Snapshot snapshot() {
    return new Snapshot(
        originalArchiveParses,
        sourceArchiveParses,
        compilerInvocations,
        reproductionCacheHits,
        physicalInventoryParses,
        physicalInventoryCacheHits,
        physicalInventoryReusesFromReproduction);
  }

  private static void requireStableFile(final Path path, final String expectedSha256)
      throws IOException {
    if (!expectedSha256.equals(SourceFileDigest.sha256(path))) {
      throw new IOException("The artifact changed during source reproduction");
    }
  }

  private static String logicalClassName(final SourceReproductionResult.ClassEntry entry) {
    final String path = entry.path();
    return path.substring(0, path.length() - ".class".length());
  }

  record ReproductionKey(
      String candidateId,
      String sourcesId,
      Path originalPath,
      Path sourcesPath,
      String originalSha256,
      String sourcesSha256,
      String repositoryProvenance,
      boolean conventionalLayoutAssumed,
      String compilerIdentity,
      List<String> compilerOptions) {
    ReproductionKey {
      compilerOptions = List.copyOf(compilerOptions);
    }
  }

  record PhysicalInventoryKey(String coordinateId, Path realPath, String sha256) {}

  record PreparedReproduction(
      List<String> sourceEntries,
      List<SourceReproductionResult.ClassEntry> originalClasses,
      SourceUnitCompiler.Compilation compilation) {
    PreparedReproduction {
      sourceEntries = List.copyOf(sourceEntries);
      originalClasses = List.copyOf(originalClasses);
    }
  }

  record Snapshot(
      long originalArchiveParses,
      long sourceArchiveParses,
      long compilerInvocations,
      long reproductionCacheHits,
      long physicalInventoryParses,
      long physicalInventoryCacheHits,
      long physicalInventoryReusesFromReproduction) {}
}
