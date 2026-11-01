/* WHY: Shares complete and intentionally malformed ZIP payloads across refresh tests. */

package io.github.spockz.elider.scanner;

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
