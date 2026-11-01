/* WHY: Reopens CVE source records for live checks. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Reads current CVEList source records. */
public final class CveSourceRecordReader {
  private CveSourceRecordReader() {}

  /** Reads the canonical CVE record below the CVEList checkout. */
  public static ObservedSource read(final Path cveListGitDir, final String cveId)
      throws IOException {
    requireCanonicalInput(cveListGitDir, cveId);
    final Path sourcePath = resolveCanonicalRecord(cveListGitDir, cveId);
    return parseCurrentRecord(sourcePath, cveId);
  }

  private static void requireCanonicalInput(final Path cveListGitDir, final String cveId)
      throws IOException {
    if (cveListGitDir == null || cveId == null || !cveId.matches("CVE-[0-9]{4}-[0-9]{4,}")) {
      throw new IOException("A CVEList root and canonical CVE ID are required");
    }
  }

  private static Path resolveCanonicalRecord(final Path cveListGitDir, final String cveId)
      throws IOException {
    final String located = OsvSnapshotIndexer.locateCveRecord(cveListGitDir, cveId);
    if (located == null) {
      throw new IOException("Current CVEList source record is unavailable: " + cveId);
    }
    final Path checkoutRoot = cveListGitDir.toRealPath();
    final Path sourcePath = Path.of(located).toRealPath();
    final Path cvesRoot = checkoutRoot.resolve("cves").toRealPath();
    if (!cvesRoot.startsWith(checkoutRoot)
        || !sourcePath.startsWith(cvesRoot)
        || !Files.isRegularFile(sourcePath)) {
      throw new IOException("CVEList source record resolves outside the CVE directory");
    }
    return sourcePath;
  }

  private static ObservedSource parseCurrentRecord(final Path sourcePath, final String cveId)
      throws IOException {
    final byte[] bytes = Files.readAllBytes(sourcePath);
    final JsonNode root =
        new OsvSnapshotIndexer().readSingleJsonDocument(bytes, "CVE source record");
    if (!root.isObject()) {
      throw new IOException("CVE source record must be a JSON object");
    }
    try {
      OsvSnapshotIndexer.validateCveSourceShape(root);
      final String digest = sha256(bytes);
      final CveSourceRecordMetadata metadata =
          OsvSnapshotIndexer.readCveSourceMetadata(root, digest);
      final List<CveAffectedEntryContext> entries = readAffectedEntries(root, metadata);
      return new ObservedSource(sourcePath, digest, metadata, entries);
    } catch (final IllegalArgumentException exception) {
      throw new IOException("Invalid current CVEList source record: " + cveId, exception);
    }
  }

  private static List<CveAffectedEntryContext> readAffectedEntries(
      final JsonNode root, final CveSourceRecordMetadata metadata) {
    final JsonNode affected = root.path("containers").path("cna").path("affected");
    final List<CveAffectedEntryContext> entries = new ArrayList<>();
    if (affected.isArray()) {
      for (int index = 0; index < affected.size(); index++) {
        entries.add(OsvSnapshotIndexer.readCnaContext(affected.get(index), index, metadata));
      }
    }
    return List.copyOf(entries);
  }

  private static String sha256(final byte[] bytes) throws IOException {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IOException("SHA-256 is unavailable", exception);
    }
  }

  /** Immutable current source bytes and every independently located CNA entry. */
  public record ObservedSource(
      Path sourcePath,
      String sourceRecordSha256,
      CveSourceRecordMetadata metadata,
      List<CveAffectedEntryContext> affectedEntries) {
    /** Normalizes the path and freezes the current source-entry observations. */
    public ObservedSource {
      sourcePath = sourcePath.toAbsolutePath().normalize();
      affectedEntries = List.copyOf(affectedEntries);
    }
  }
}
