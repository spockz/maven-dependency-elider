/* WHY: Replaces source-derived cache associations by their OSV record owner ID. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.OsvAdvisoryRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/** Applies only modified OSV source records to a staged owner-indexed snapshot. */
/* Package access keeps owner reconciliation internal to cache refresh. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class OsvDeltaRecordUpdater {
  /** Parses the complete upstream change list. */
  private final OsvModifiedIdReader modifiedIdReader;

  /** Rebuilds each changed OSV owner's derived evidence. */
  private final OsvSnapshotIndexer indexer;

  /** Creates source parsers used by one refresh. */
  // The default access modifier keeps construction inside the cache package.
  OsvDeltaRecordUpdater() {
    modifiedIdReader = new OsvModifiedIdReader();
    indexer = new OsvSnapshotIndexer();
  }

  /** Replaces by owner ID, preserves input on failure, and sorts output by ID. */
  // The default access modifier keeps reconciliation internal to the cache package.
  List<OsvAdvisoryRecord> apply(
      final InputStream modifiedIndex,
      final List<OsvAdvisoryRecord> baseRecords,
      final Path cveListGitDir,
      final RecordFetcher recordFetcher)
      throws IOException {
    Objects.requireNonNull(baseRecords, "baseRecords");
    Objects.requireNonNull(recordFetcher, "recordFetcher");
    final Map<String, OsvAdvisoryRecord> recordsById = indexById(baseRecords);
    final List<OsvModifiedIdReader.ModifiedId> modifiedRows = new ArrayList<>();
    modifiedIdReader.read(modifiedIndex, modifiedRows::add);
    modifiedRows.sort(
        Comparator.comparing(OsvModifiedIdReader.ModifiedId::recordId)
            .thenComparing(OsvModifiedIdReader.ModifiedId::modified));
    int rowIndex = 0;
    while (rowIndex < modifiedRows.size()) {
      final OsvModifiedIdReader.ModifiedId revision = modifiedRows.get(rowIndex);
      int nextIndex = rowIndex + 1;
      while (nextIndex < modifiedRows.size()
          && modifiedRows.get(nextIndex).recordId().equals(revision.recordId())) {
        nextIndex++;
      }
      replaceIfNewer(modifiedRows.get(nextIndex - 1), recordsById, cveListGitDir, recordFetcher);
      rowIndex = nextIndex;
    }
    return recordsById.values().stream()
        .sorted(Comparator.comparing(OsvAdvisoryRecord::osvId))
        .toList();
  }

  private static Map<String, OsvAdvisoryRecord> indexById(final List<OsvAdvisoryRecord> baseRecords)
      throws IOException {
    final Set<String> seenIds = new HashSet<>();
    for (final OsvAdvisoryRecord record : baseRecords) {
      if (!seenIds.add(record.osvId())) {
        throw new IOException("Duplicate OSV record ID in base snapshot: " + record.osvId());
      }
    }
    return baseRecords.stream()
        .collect(Collectors.toMap(OsvAdvisoryRecord::osvId, Function.identity()));
  }

  private void replaceIfNewer(
      final OsvModifiedIdReader.ModifiedId revision,
      final Map<String, OsvAdvisoryRecord> recordsById,
      final Path cveListGitDir,
      final RecordFetcher recordFetcher)
      throws IOException {
    final String recordId = revision.recordId();
    final Instant modified = revision.modified();
    final OsvAdvisoryRecord previous = recordsById.get(recordId);
    if (!isNewer(modified, previous)) {
      return;
    }
    final OsvSnapshotIndexer.IndexedOsvRecord replacement =
        indexer.indexRecord(recordFetcher.fetch(recordId), cveListGitDir, recordId);
    final Instant fetchedModified = Instant.parse(replacement.modified());
    if (fetchedModified.isBefore(modified)
        || (previous != null && fetchedModified.isBefore(Instant.parse(previous.modified())))) {
      throw new IOException("Fetched OSV record is older than selected revision: " + recordId);
    }
    if (replacement.advisory().isPresent()) {
      recordsById.put(recordId, replacement.advisory().orElseThrow());
    } else {
      recordsById.remove(recordId);
    }
  }

  private static boolean isNewer(final Instant modified, final OsvAdvisoryRecord previous) {
    return previous == null || modified.isAfter(Instant.parse(previous.modified()));
  }

  /** Fetches one exact upstream OSV record document. */
  @FunctionalInterface
  // The default access modifier keeps the callback internal to the cache package.
  interface RecordFetcher {
    /** Retrieves one record by its OSV ID. */
    byte[] fetch(String recordId) throws IOException;
  }
}
