/* WHY: Distinguishes corrupt cache entries, unchanged archives, and
 * validated cached outputs before a manifest can be accepted. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** Validates one cached archive against its current source and output bytes. */
final class TrimCacheLookup {
  private TrimCacheLookup() {}

  /** Cache states distinguish a miss from a valid unchanged archive. */
  /* package */ sealed interface EntryLookup permits MissingEntry, UnchangedEntry, CachedArchive {}

  /** A corrupt or stale entry causes the containing manifest to miss. */
  /* package */ enum MissingEntry implements EntryLookup {
    INSTANCE
  }

  /** An unchanged archive needs no generated output record. */
  /* package */ enum UnchangedEntry implements EntryLookup {
    INSTANCE
  }

  /* package */ record CachedArchive(ArtifactTrimRecord record) implements EntryLookup {}

  /* package */ static EntryLookup readEntry(
      final CacheEntry entry,
      final TrimCandidate candidate,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final Path original = candidate.archive().snapshot().filePath().toAbsolutePath().normalize();
    final ArtifactDigests digests = TrimInputDigests.requiredInputDigest(inputDigests, original);
    if (!TrimCacheValidator.validCacheEntry(entry, candidate)) {
      return MissingEntry.INSTANCE;
    }
    if (!validOriginal(entry, original, digests)) {
      return MissingEntry.INSTANCE;
    }
    if (entry.trimmedPath() == null) {
      return UnchangedEntry.INSTANCE;
    }
    return readOutput(entry, candidate, original);
  }

  private static boolean validOriginal(
      final CacheEntry entry, final Path original, final ArtifactDigests digests)
      throws IOException {
    return original.toString().equals(entry.originalPath())
        && digests.sha256().equals(entry.originalSha256())
        && matchingEntryCount(entry, original)
        && (entry.trimmedPath() == null || digests.sha1().equals(entry.originalSha1()));
  }

  private static boolean matchingEntryCount(final CacheEntry entry, final Path original)
      throws IOException {
    return entry.originalPhysicalEntries() == null
        || entry.originalPhysicalEntries() == TrimCacheValidator.physicalEntryCount(original);
  }

  private static EntryLookup readOutput(
      final CacheEntry entry, final TrimCandidate candidate, final Path original)
      throws IOException {
    final Path output = candidate.output().toAbsolutePath().normalize();
    if (!output.toString().equals(entry.trimmedPath()) || !Files.isRegularFile(output)) {
      return MissingEntry.INSTANCE;
    }
    final ArtifactDigests digests = ArtifactDigests.read(output);
    if (!entry.trimmedSha256().equals(digests.sha256())
        || !entry.trimmedSha1().equals(digests.sha1())
        || entry.trimmedPhysicalEntries() != TrimCacheValidator.physicalEntryCount(output)) {
      return MissingEntry.INSTANCE;
    }
    return new CachedArchive(
        new ArtifactTrimRecord(
            candidate.archive().snapshot().coordinate(),
            original.toRealPath(),
            entry.originalSha256(),
            entry.originalSha1(),
            output.toRealPath(),
            entry.trimmedSha256(),
            entry.trimmedSha1(),
            entry.totalClasses(),
            entry.retainedClasses(),
            entry.prunedClassBytes(),
            entry.originalPhysicalEntries(),
            entry.trimmedPhysicalEntries(),
            entry.mrjarStatus()));
  }
}
