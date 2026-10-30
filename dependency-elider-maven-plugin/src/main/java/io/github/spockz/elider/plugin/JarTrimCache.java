/* WHY: Owns cache serialization and digest checks so corrupt or stale
 * manifests cannot replace current trim evidence. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads and writes validated trim cache envelopes. */
final class JarTrimCache {
  /** Uses one strict mapper for the cache envelope and canonical identity bytes. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  private JarTrimCache() {}

  /* package */ record CacheManifest(
      int schemaVersion, String formatId, String fingerprint, List<CacheEntry> entries) {}

  /* package */ record CacheOutputMetadata(
      String originalSha1,
      String trimmedPath,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      long prunedClassBytes,
      Integer originalPhysicalEntries,
      Integer trimmedPhysicalEntries,
      String mrjarStatus) {}

  /* package */ record CacheEntry(
      String originalPath,
      String originalSha256,
      String originalSha1,
      String trimmedPath,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      Long prunedClassBytes,
      Set<String> roots,
      Set<String> retainedClassNames,
      Set<String> reachableLibraryClasses,
      Integer originalPhysicalEntries,
      Integer trimmedPhysicalEntries,
      String mrjarStatus) {}

  /* package */ static CacheEntry cacheEntry(
      final TrimCandidate candidate,
      final ArtifactTrimRecord record,
      final Map<Path, ArtifactDigests> inputDigests) {
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    final ArtifactDigests originalDigests =
        TrimInputDigests.requiredInputDigest(
            inputDigests, candidate.archive().snapshot().filePath());
    final CacheOutputMetadata output =
        cacheOutputMetadata(candidate, record, analysis, originalDigests);
    return new CacheEntry(
        candidate.archive().snapshot().filePath().toAbsolutePath().normalize().toString(),
        originalDigests.sha256(),
        output.originalSha1(),
        output.trimmedPath(),
        output.trimmedSha256(),
        output.trimmedSha1(),
        output.totalClasses(),
        output.retainedClasses(),
        output.prunedClassBytes(),
        candidate.targetRoots(),
        TrimCollections.sortedSet(analysis.retainedClasses()),
        TrimCollections.sortedSet(analysis.reachableLibraryClasses()),
        output.originalPhysicalEntries(),
        output.trimmedPhysicalEntries(),
        output.mrjarStatus());
  }

  private static CacheOutputMetadata cacheOutputMetadata(
      final TrimCandidate candidate,
      final ArtifactTrimRecord record,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests) {
    if (record == null) {
      return new CacheOutputMetadata(
          null,
          null,
          null,
          null,
          candidate.archive().logicalClassCount(),
          analysis.retainedClasses().size(),
          0L,
          null,
          null,
          "not_multi_release");
    }
    return new CacheOutputMetadata(
        originalDigests.sha1(),
        record.trimmedPath().toString(),
        record.trimmedSha256(),
        record.trimmedSha1(),
        record.totalClasses(),
        record.retainedClasses(),
        record.prunedClassBytes(),
        record.originalPhysicalEntries().orElseThrow(),
        record.trimmedPhysicalEntries().orElseThrow(),
        record.mrjarStatus());
  }

  /* package */ static TrimResult loadCache(
      final Path manifestPath,
      final String fingerprint,
      final Map<Path, ArtifactDigests> inputDigests,
      final List<TrimCandidate> candidates,
      final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      final List<ArtifactCoordinate> configuredPassThroughArtifacts,
      final long started)
      throws IOException {
    if (!Files.isRegularFile(manifestPath)) {
      return null;
    }
    final CacheManifest manifest = readManifest(manifestPath);
    if (!validManifest(manifest, fingerprint, candidates.size())) {
      return null;
    }
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    for (int index = 0; index < candidates.size(); index++) {
      switch (TrimCacheLookup.readEntry(
          manifest.entries().get(index), candidates.get(index), inputDigests)) {
        case TrimCacheLookup.MissingEntry ignored -> {
          return null;
        }
        case TrimCacheLookup.UnchangedEntry ignored -> {}
        case TrimCacheLookup.CachedArchive cached -> records.add(cached.record());
      }
    }
    return new TrimResult(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        records.size(),
        System.nanoTime() - started,
        0);
  }

  private static CacheManifest readManifest(final Path path) {
    try {
      return JSON.readValue(path.toFile(), CacheManifest.class);
    } catch (final IOException exception) {
      return null;
    }
  }

  private static boolean validManifest(
      final CacheManifest manifest, final String fingerprint, final int candidateCount) {
    return manifest != null
        && manifest.schemaVersion() == MavenDependencyTrimmer.CACHE_SCHEMA_VERSION
        && MavenDependencyTrimmer.CACHE_FORMAT_ID.equals(manifest.formatId())
        && manifest.entries() != null
        && fingerprint.equals(manifest.fingerprint())
        && manifest.entries().size() == candidateCount;
  }

  /* package */ static void storeCache(final Path manifestPath, final CacheManifest manifest)
      throws IOException {
    final Path parent = manifestPath.getParent();
    if (parent == null) {
      throw new IOException("Trim cache manifest has no parent directory: " + manifestPath);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".trim-cache-", ".json.tmp");
    try {
      JSON.writeValue(temporary.toFile(), manifest);
      Files.move(
          temporary,
          manifestPath,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  /* package */ static byte[] serializeIdentity(
      final EffectiveTrimCacheContext.EffectiveCacheIdentity identity)
      throws com.fasterxml.jackson.core.JsonProcessingException {
    return JSON.writeValueAsBytes(identity);
  }

  /* package */ static void writeManifest(final Path path, final CacheManifest manifest)
      throws IOException {
    JSON.writeValue(path.toFile(), manifest);
  }

  /* package */ static List<CacheEntry> orderedEntries(
      final List<TrimCandidate> work,
      final Map<TrimCandidate, CacheEntry> entries,
      final String missingPrefix)
      throws IOException {
    final List<CacheEntry> ordered = new ArrayList<>(work.size());
    for (final TrimCandidate candidate : work) {
      ordered.add(requiredEntry(candidate, entries, missingPrefix));
    }
    return ordered;
  }

  private static CacheEntry requiredEntry(
      final TrimCandidate candidate,
      final Map<TrimCandidate, CacheEntry> entries,
      final String missingPrefix)
      throws IOException {
    final CacheEntry entry = entries.get(candidate);
    if (entry == null) {
      throw new IOException(missingPrefix + candidate.archive().snapshot().coordinate());
    }
    return entry;
  }
}
