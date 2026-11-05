/* WHY: Reads CVE records tolerantly for indexing without weakening live verification reads. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Isolates malformed CVE rows while retaining current source bytes. */
@SuppressWarnings("PMD.CommentRequired")
final class CveSourceRecordIndexReader {
  /** Maximum malformed-row samples retained from one record. */
  private static final int MAX_SKIPPED_ENTRY_SAMPLES = 1024;

  private static final String CONTAINERS = "containers";
  private static final String CNA = "cna";
  private static final String ADP = "adp";
  private static final String AFFECTED = "affected";
  private static final String PUBLISHED = "PUBLISHED";
  private static final String REJECTED = "REJECTED";

  private CveSourceRecordIndexReader() {}

  /** Skips malformed source data during indexing. */
  /* default */ static IndexingResult read(final Path cveListGitDir, final String cveId)
      throws IOException {
    CveSourceRecordReader.requireCanonicalInput(cveListGitDir, cveId);
    final Path sourcePath = CveSourceRecordReader.resolveCanonicalRecord(cveListGitDir, cveId);
    final byte[] bytes = Files.readAllBytes(sourcePath);
    final String digest = CveSourceRecordReader.sha256(bytes);
    final JsonNode root;
    try {
      root = new OsvSnapshotIndexer().readSingleJsonDocument(bytes, "CVE source record");
    } catch (final IOException malformedJson) {
      return skippedRecord(digest, "record", describe(malformedJson));
    }
    if (!root.isObject()) {
      return skippedRecord(digest, "record", "CVE source record must be a JSON object");
    }
    try {
      OsvSnapshotIndexer.validateCveSourceRecordShape(root);
      final CveSourceRecordMetadata metadata =
          OsvSnapshotIndexer.readCveSourceMetadata(root, digest);
      validateMetadata(metadata, cveId);
      if (PUBLISHED.equals(metadata.state()) && root.get(CONTAINERS) == null) {
        return skippedRecord(digest, CONTAINERS, "Published CVE record has no containers");
      }
      final AffectedEntries affected = readAffectedEntries(root, metadata);
      final CveSourceRecordReader.ObservedSource source =
          new CveSourceRecordReader.ObservedSource(
              sourcePath, digest, metadata, affected.entries());
      return new IndexingResult(
          Optional.of(source),
          digest,
          affected.skippedRows(),
          affected.skippedEntries(),
          affected.truncated());
    } catch (final IllegalArgumentException malformedRecord) {
      return skippedRecord(digest, "record", describe(malformedRecord));
    }
  }

  private static void validateMetadata(
      final CveSourceRecordMetadata metadata, final String requestedCveId) {
    final boolean identityMatches =
        metadata.cveMetadataPresent()
            && metadata.cveMetadataObject()
            && metadata.cveIdPresent()
            && requestedCveId.equals(metadata.cveId());
    final boolean recognizedState =
        metadata.statePresent()
            && (PUBLISHED.equals(metadata.state()) || REJECTED.equals(metadata.state()));
    if (!identityMatches) {
      throw new IllegalArgumentException("CVE record metadata identity is missing or mismatched");
    }
    if (!recognizedState) {
      throw new IllegalArgumentException("CVE record metadata state is missing or unrecognized");
    }
  }

  private static IndexingResult skippedRecord(
      final String digest, final String locator, final String reason) {
    return new IndexingResult(
        Optional.empty(), digest, 1, List.of(new SkippedEntry(locator, reason)), false);
  }

  private static AffectedEntries readAffectedEntries(
      final JsonNode root, final CveSourceRecordMetadata metadata) {
    final EntryAccumulator entries = new EntryAccumulator();
    final JsonNode containers = root.path(CONTAINERS);
    readCna(containers, metadata, entries);
    readAdp(containers, metadata, entries);
    return entries.snapshot();
  }

  private static void readCna(
      final JsonNode containers,
      final CveSourceRecordMetadata metadata,
      final EntryAccumulator entries) {
    final boolean published = PUBLISHED.equals(metadata.state());
    final JsonNode cna = containers.get(CNA);
    if (cna == null) {
      if (published) {
        entries.skip("containers.cna.affected", "Published CVE record has no CNA affected array");
      }
      return;
    }
    if (!cna.isObject()) {
      entries.skip("containers.cna", "containers.cna must be an object");
      return;
    }
    final JsonNode affected = cna.get(AFFECTED);
    if (affected == null) {
      if (published) {
        entries.skip("containers.cna.affected", "Published CVE record has no CNA affected array");
      }
      return;
    }
    if (!affected.isArray()) {
      entries.skip("containers.cna.affected", "containers.cna.affected must be an array");
      return;
    }
    appendEntries(entries, affected, "containers.cna", metadata);
  }

  private static void readAdp(
      final JsonNode containers,
      final CveSourceRecordMetadata metadata,
      final EntryAccumulator entries) {
    final JsonNode adp = containers.get(ADP);
    if (adp == null) {
      return;
    }
    if (!adp.isArray()) {
      entries.skip("containers.adp", "containers.adp must be an array");
      return;
    }
    for (int adpIndex = 0; adpIndex < adp.size(); adpIndex++) {
      final String containerPath = "containers.adp[" + adpIndex + "]";
      final JsonNode container = adp.get(adpIndex);
      if (!container.isObject()) {
        entries.skip(containerPath, containerPath + " must be an object");
        continue;
      }
      final JsonNode affected = container.get(AFFECTED);
      if (affected == null) {
        continue;
      }
      if (!affected.isArray()) {
        entries.skip(containerPath + ".affected", containerPath + ".affected must be an array");
        continue;
      }
      appendEntries(entries, affected, containerPath, metadata);
    }
  }

  private static void appendEntries(
      final EntryAccumulator entries,
      final JsonNode affected,
      final String containerPath,
      final CveSourceRecordMetadata metadata) {
    for (int index = 0; index < affected.size(); index++) {
      final String locator = containerPath + ".affected[" + index + "]";
      try {
        OsvSnapshotIndexer.validateCveAffectedEntry(affected.get(index), containerPath, index);
        entries.add(
            OsvSnapshotIndexer.readCveAffectedContext(
                affected.get(index), containerPath, index, metadata));
      } catch (final IllegalArgumentException malformedEntry) {
        entries.skip(locator, describe(malformedEntry));
      }
    }
  }

  private static String describe(final Exception failure) {
    final String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.getClass().getSimpleName() : message;
  }

  /** Raw record and bounded malformed-row observations for one indexing attempt. */
  /* default */ record IndexingResult(
      Optional<CveSourceRecordReader.ObservedSource> source,
      String sourceRecordSha256,
      int skippedRows,
      List<SkippedEntry> skippedEntries,
      boolean skippedEntryDetailsTruncated) {
    IndexingResult {
      source = java.util.Objects.requireNonNull(source, "source");
      if (sourceRecordSha256 == null || !sourceRecordSha256.matches("[0-9a-f]{64}")) {
        throw new IllegalArgumentException("source record digest must be SHA-256");
      }
      if (skippedRows < 0) {
        throw new IllegalArgumentException("skipped row count must not be negative");
      }
      skippedEntries = List.copyOf(skippedEntries);
      if (skippedEntries.size() > MAX_SKIPPED_ENTRY_SAMPLES
          || skippedEntries.size() > skippedRows) {
        throw new IllegalArgumentException("skipped row samples exceed their count");
      }
      if (skippedEntryDetailsTruncated && skippedEntries.size() != MAX_SKIPPED_ENTRY_SAMPLES) {
        throw new IllegalArgumentException("truncated samples must reach the sample limit");
      }
    }
  }

  /** One invalid affected entry retained for diagnostic reporting. */
  /* default */ record SkippedEntry(String locator, String reason) {
    SkippedEntry {
      if (locator == null || locator.isBlank() || reason == null || reason.isBlank()) {
        throw new IllegalArgumentException("skipped entry locator and reason must be non-blank");
      }
    }
  }

  private record AffectedEntries(
      List<CveAffectedEntryContext> entries,
      int skippedRows,
      List<SkippedEntry> skippedEntries,
      boolean truncated) {}

  @SuppressWarnings("PMD.CommentRequired")
  private static final class EntryAccumulator {
    private final List<CveAffectedEntryContext> entries = new ArrayList<>();
    private final List<SkippedEntry> skippedEntries = new ArrayList<>();
    private int skippedRows;
    private boolean truncated;

    private void add(final CveAffectedEntryContext entry) {
      entries.add(entry);
    }

    private void skip(final String locator, final String reason) {
      skippedRows++;
      if (skippedEntries.size() < MAX_SKIPPED_ENTRY_SAMPLES) {
        skippedEntries.add(new SkippedEntry(locator, reason));
      } else {
        truncated = true;
      }
    }

    private AffectedEntries snapshot() {
      return new AffectedEntries(
          List.copyOf(entries), skippedRows, List.copyOf(skippedEntries), truncated);
    }
  }
}
