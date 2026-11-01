// WHY: Holds only verified physical class digests or exact Java source bytes needed for
// reproduction.

package io.github.spockz.elider.correspondence;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Immutable view of one validated archive used by source correspondence. */
final class SourceCorrespondenceArchive {
  /** Digest used to detect source archive mutation across reproduction. */
  private final String archiveDigest;

  /** Private copies prevent compilation callers from changing retained archive bytes. */
  private final Map<String, byte[]> sourceContents;

  /** Complete binary inventory or the empty inventory for a source archive. */
  private final List<SourceReproductionResult.ClassEntry> classEntries;

  /** Stable names used to create one compilation task per source unit. */
  private final List<String> entryNames;

  /* default */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // Defensive copying uses a private local map.
  SourceCorrespondenceArchive(
      final String sha256,
      final Map<String, byte[]> sourceContents,
      final List<SourceReproductionResult.ClassEntry> classes,
      final List<String> sourceEntries) {
    this.archiveDigest = sha256;
    final Map<String, byte[]> copiedContents = new HashMap<>();
    sourceContents.forEach((path, bytes) -> copiedContents.put(path, bytes.clone()));
    this.sourceContents = Collections.unmodifiableMap(copiedContents);
    this.classEntries = List.copyOf(classes);
    this.entryNames = List.copyOf(sourceEntries);
  }

  /* default */ String sha256() {
    return archiveDigest;
  }

  /* default */ byte[] sourceContent(final String entry) {
    final byte[] bytes = sourceContents.get(entry);
    if (bytes == null) {
      throw new IllegalArgumentException("Source content is unavailable for " + entry);
    }
    return bytes.clone();
  }

  /* default */ List<SourceReproductionResult.ClassEntry> classes() {
    return classEntries;
  }

  /* default */ List<String> sourceEntries() {
    return entryNames;
  }
}
