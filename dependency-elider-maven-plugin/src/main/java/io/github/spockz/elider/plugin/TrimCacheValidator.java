/* WHY: Validates cached counts, class evidence, and output metadata before
 * cached archives are accepted. */

package io.github.spockz.elider.plugin;

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
    return validDigest(entry.originalSha256(), 64)
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
          && entry.originalPhysicalEntries() == null
          && entry.trimmedPhysicalEntries() == null
          && entry.retainedClasses() == entry.totalClasses()
          && entry.originalSha1() == null
          && entry.trimmedSha256() == null
          && entry.trimmedSha1() == null;
    }
    return validDigest(entry.originalSha1(), 40)
        && validDigest(entry.trimmedSha256(), 64)
        && validDigest(entry.trimmedSha1(), 40)
        && entry.originalPhysicalEntries() != null
        && entry.trimmedPhysicalEntries() != null
        && entry.originalPhysicalEntries() >= 0
        && entry.trimmedPhysicalEntries() >= 0
        && (entry.retainedClasses() < entry.totalClasses() || candidate.archive().multiRelease());
  }

  private static boolean validDigest(final String value, final int length) {
    return HexDigest.isLowercaseHex(value, length);
  }

  /* package */ static int physicalEntryCount(final Path archivePath) throws IOException {
    int count = 0;
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final java.util.Enumeration<java.util.jar.JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        entries.nextElement();
        count = Math.addExact(count, 1);
      }
    } catch (final ArithmeticException exception) {
      throw new IOException("Archive entry count overflowed: " + archivePath, exception);
    }
    return count;
  }
}
