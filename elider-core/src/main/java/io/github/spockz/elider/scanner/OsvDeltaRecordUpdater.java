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

  /** Applies changed owners and retains skipped-row diagnostics. */
  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.UseConcurrentHashMap"
  })
  OsvSnapshotIndexer.PartialIndex applyIsolated(
      final InputStream modifiedIndex,
      final List<OsvAdvisoryRecord> baseRecords,
      final Path cveListGitDir,
      final RecordFetcher recordFetcher,
      final Set<String> quarantinedIds,
      final Map<String, String> previousWithdrawals)
      throws IOException {
    final Map<String, OsvAdvisoryRecord> recordsById = indexById(baseRecords);
    final Map<String, String> withdrawals = new java.util.HashMap<>(previousWithdrawals);
    final List<OsvModifiedIdReader.ModifiedId> modifiedRows = new ArrayList<>();
    modifiedIdReader.read(modifiedIndex, modifiedRows::add);
    modifiedRows.sort(
        Comparator.comparing(OsvModifiedIdReader.ModifiedId::recordId)
            .thenComparing(OsvModifiedIdReader.ModifiedId::modified));
    final List<String> skipped = new ArrayList<>();
    int index = 0;
    while (index < modifiedRows.size()) {
      int next = index + 1;
      while (next < modifiedRows.size()
          && modifiedRows.get(next).recordId().equals(modifiedRows.get(index).recordId())) {
        next++;
      }
      final OsvModifiedIdReader.ModifiedId revision = modifiedRows.get(next - 1);
      final OsvAdvisoryRecord previous = recordsById.get(revision.recordId());
      final String withdrawnRevision = withdrawals.get(revision.recordId());
      if (!quarantinedIds.contains(revision.recordId())
          && isNewer(revision.modified(), previous)
          && (withdrawnRevision == null
              || revision.modified().isAfter(Instant.parse(withdrawnRevision)))) {
        final byte[] bytes = recordFetcher.fetch(revision.recordId());
        final OsvSnapshotIndexer.PartialRecord partial;
        try {
          partial = indexer.indexRecordIsolated(bytes, cveListGitDir, revision.recordId());
        } catch (final IOException | IllegalArgumentException invalid) {
          recordsById.remove(revision.recordId());
          skipped.add(
              OsvSnapshotIndexer.skippedRecord(revision.recordId(), bytes, invalid.getMessage()));
          index = next;
          continue;
        }
        final OsvSnapshotIndexer.IndexedOsvRecord replacement = partial.record();
        skipped.addAll(partial.skippedRows());
        final Instant fetchedModified = Instant.parse(replacement.modified());
        if (fetchedModified.isBefore(revision.modified())
            || (previous != null && fetchedModified.isBefore(Instant.parse(previous.modified())))) {
          throw new IOException(
              "Fetched OSV record is older than selected revision: " + revision.recordId());
        }
        if (replacement.advisory().isPresent()) {
          recordsById.put(revision.recordId(), replacement.advisory().orElseThrow());
          withdrawals.remove(revision.recordId());
        } else {
          recordsById.remove(revision.recordId());
          withdrawals.put(revision.recordId(), replacement.modified());
        }
      }
      index = next;
    }
    return new OsvSnapshotIndexer.PartialIndex(
        recordsById.values().stream()
            .sorted(Comparator.comparing(OsvAdvisoryRecord::osvId))
            .toList(),
        skipped,
        skipped.size(),
        Set.of(),
        withdrawals);
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
