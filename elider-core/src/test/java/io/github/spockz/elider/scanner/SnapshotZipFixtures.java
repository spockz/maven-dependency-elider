/* WHY: Shares snapshot and malformed cache fixtures across refresh tests. */

package io.github.spockz.elider.scanner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/** Creates source ZIP payloads for cache refresh tests. */
public final class SnapshotZipFixtures {
  /** Creates the static test-fixture utility. */
  private SnapshotZipFixtures() {}

  /** Writes records as valid OSV source JSON entries. */
  public static byte[] snapshot(final OsvAdvisoryRecord... records) throws IOException {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      for (final OsvAdvisoryRecord record : records) {
        writeRecord(zip, record);
      }
    }
    return output.toByteArray();
  }

  private static void writeRecord(final ZipOutputStream zip, final OsvAdvisoryRecord record)
      throws IOException {
    zip.putNextEntry(new ZipEntry(record.osvId() + ".json"));
    zip.write(
        OsvSnapshotFixtures.osvJson(
                record.osvId(), record.aliases().stream().findFirst().orElse(null))
            .getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  /** Writes caller-supplied JSON entries for malformed-source tests. */
  public static byte[] raw(final String... filesAndJson) throws IOException {
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      for (int index = 0; index < filesAndJson.length; index += 2) {
        writeEntry(zip, filesAndJson[index], filesAndJson[index + 1]);
      }
    }
    return output.toByteArray();
  }

  private static void writeEntry(
      final ZipOutputStream zip, final String name, final String contents) throws IOException {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(contents.getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  /** Creates a syntactically valid ZIP containing malformed JSON. */
  public static byte[] malformedJson() throws IOException {
    return raw("malformed.json", "{not-json");
  }

  /** Writes typed cache bytes with an invalid present CNA version type. */
  public static byte[] invalidVersionTypeCache() throws IOException {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode root = mapper.createObjectNode();
    root.put("schemaVersion", 1);
    final ArrayNode records = root.putArray("records");
    final ObjectNode record = records.addObject();
    record.put("osvId", "GHSA-bad");
    record.put("modified", "2026-10-31T00:00:00Z");
    record.putArray("aliases");
    record.putArray("affectedPackages");
    final ObjectNode entry = record.putArray("cnaAffectedEntries").addObject();
    entry.put("entryIdentity", "containers.cna.affected[0]");
    final ObjectNode sourceRecord = entry.putObject("sourceRecord");
    sourceRecord.put("cveMetadataPresent", false);
    sourceRecord.put("cveMetadataObject", false);
    sourceRecord.put("cveIdPresent", false);
    sourceRecord.putNull("cveId");
    sourceRecord.put("statePresent", false);
    sourceRecord.putNull("state");
    sourceRecord.put("sourceRecordSha256", "a".repeat(64));
    entry.putNull("vendor");
    entry.put("product", "demo");
    entry.putNull("packageUrl");
    entry.putNull("collectionUrl");
    entry.putNull("packageName");
    entry.putNull("defaultStatus");
    final ObjectNode version = entry.putArray("versions").addObject();
    version.put("version", "1.0");
    version.put("status", "affected");
    version.put("versionType", "");
    version.putNull("lessThan");
    version.putNull("lessThanOrEqual");
    version.putArray("changes");
    entry.putArray("programFiles");
    entry.putArray("programRoutines");
    record.putArray("evidence");
    return mapper.writeValueAsBytes(root);
  }

  /** Removes the central directory to simulate a truncated ZIP. */
  public static byte[] withoutCentralDirectory(final byte[] completeZip) {
    for (int index = 0; index + 3 < completeZip.length; index++) {
      if (completeZip[index] == 0x50
          && completeZip[index + 1] == 0x4b
          && completeZip[index + 2] == 0x01
          && completeZip[index + 3] == 0x02) {
        return Arrays.copyOf(completeZip, index);
      }
    }
    throw new IllegalArgumentException("Fixture ZIP has no central directory");
  }
}
