/* WHY: Validates cached counts, class evidence, and output metadata before
 * cached archives are accepted. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.plugin.JarTrimCache.CacheEntry;
import java.io.IOException;
import java.nio.file.Path;
import java.util.jar.JarFile;

/** Checks cached metadata and output counts against current candidates. */
final class TrimCacheValidator {
  private TrimCacheValidator() {}

  /* package */ static boolean validCacheEntry(
      final CacheEntry entry, final TrimCandidate candidate) {
    if (entry == null) {
      return false;
    }
    return validCacheMetadata(entry, candidate)
        && TrimCacheEvidence.validRetainedClassEvidence(entry, candidate)
        && validCacheOutput(entry, candidate);
  }

  private static boolean validCacheMetadata(final CacheEntry entry, final TrimCandidate candidate) {
    return validCacheCollections(entry)
        && validCacheCounts(entry, candidate)
        && validCacheStatus(entry, candidate)
        && candidate.targetRoots().containsAll(entry.roots());
  }

  private static boolean validCacheCollections(final CacheEntry entry) {
    return HexDigest.isLowercaseHex(entry.originalSha256(), 64)
        && entry.roots() != null
        && !entry.roots().contains(null)
        && entry.retainedClassNames() != null
        && !entry.retainedClassNames().contains(null)
        && entry.prunedClassBytes() != null
        && entry.prunedClassBytes() >= 0
        && entry.reachableLibraryClasses() != null
        && !entry.reachableLibraryClasses().contains(null);
  }

  private static boolean validCacheCounts(final CacheEntry entry, final TrimCandidate candidate) {
    return entry.totalClasses() == candidate.archive().logicalClassCount()
        && entry.retainedClasses() >= 0
        && entry.retainedClasses() <= entry.totalClasses()
        && (candidate.archive().multiRelease()
            || entry.retainedClassNames().size() == entry.retainedClasses());
  }

  private static boolean validCacheStatus(final CacheEntry entry, final TrimCandidate candidate) {
    if (candidate.archive().multiRelease()) {
      return "elevated_and_trimmed".equals(entry.mrjarStatus());
    }
    return "not_multi_release".equals(entry.mrjarStatus())
        || "classpath-only".equals(entry.mrjarStatus());
  }

  private static boolean validCacheOutput(final CacheEntry entry, final TrimCandidate candidate) {
    if (entry.trimmedPath() == null) {
      return !candidate.archive().multiRelease()
          && !candidate.requiresOutput()
          && entry.originalPhysicalEntries() == null
          && entry.trimmedPhysicalEntries() == null
          && entry.retainedClasses() == entry.totalClasses()
          && entry.originalSha1() == null
          && entry.trimmedSha256() == null
          && entry.trimmedSha1() == null;
    }
    return HexDigest.isLowercaseHex(entry.originalSha1(), 40)
        && HexDigest.isLowercaseHex(entry.trimmedSha256(), 64)
        && HexDigest.isLowercaseHex(entry.trimmedSha1(), 40)
        && entry.originalPhysicalEntries() != null
        && entry.trimmedPhysicalEntries() != null
        && entry.originalPhysicalEntries() >= 0
        && entry.trimmedPhysicalEntries() >= 0
        && (entry.retainedClasses() < entry.totalClasses()
            || candidate.archive().multiRelease()
            || !entry.trimmedPhysicalEntries().equals(entry.originalPhysicalEntries())
            || !entry.originalSha256().equals(entry.trimmedSha256()));
  }

  /* package */ static int physicalEntryCount(final Path archivePath) throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.size();
    }
  }
}
