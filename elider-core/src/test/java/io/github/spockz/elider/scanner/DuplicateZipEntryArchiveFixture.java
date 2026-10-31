/* WHY: Creates a physical ZIP with duplicate names for archive-validation tests. */

package io.github.spockz.elider.scanner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.CRC32;

/** Creates a duplicate-name ZIP that standard writers refuse to produce. */
public final class DuplicateZipEntryArchiveFixture {
  /** Entry name repeated in both the local headers and central directory. */
  private static final String ENTRY_NAME = "duplicate.txt";

  /** Payload shared by the duplicated archive records. */
  private static final byte[] CONTENTS = "duplicate".getBytes(StandardCharsets.UTF_8);

  private record StoredEntry(String name, byte[] contents, long crc32, int localOffset) {}

  private DuplicateZipEntryArchiveFixture() {
    throw new AssertionError("Utility class");
  }

  /** Writes the duplicate-name archive at the requested path. */
  public static void write(final Path path) throws IOException {
    final ByteArrayOutputStream archive = new ByteArrayOutputStream();
    final StoredEntry first = writeLocalEntry(archive);
    final StoredEntry second = writeLocalEntry(archive);
    final int centralOffset = archive.size();
    writeCentralEntry(archive, first);
    writeCentralEntry(archive, second);
    writeEndOfCentralDirectory(archive, centralOffset, archive.size() - centralOffset);
    Files.write(path, archive.toByteArray());
  }

  private static StoredEntry writeLocalEntry(final ByteArrayOutputStream archive) {
    final byte[] nameBytes = ENTRY_NAME.getBytes(StandardCharsets.UTF_8);
    final CRC32 crc = new CRC32();
    crc.update(CONTENTS);
    final int offset = archive.size();
    writeLittleEndianInt(archive, 0x04034b50);
    writeLittleEndianShort(archive, 20);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianInt(archive, crc.getValue());
    writeLittleEndianInt(archive, CONTENTS.length);
    writeLittleEndianInt(archive, CONTENTS.length);
    writeLittleEndianShort(archive, nameBytes.length);
    writeLittleEndianShort(archive, 0);
    archive.writeBytes(nameBytes);
    archive.writeBytes(CONTENTS);
    return new StoredEntry(ENTRY_NAME, CONTENTS, crc.getValue(), offset);
  }

  private static void writeCentralEntry(
      final ByteArrayOutputStream archive, final StoredEntry entry) {
    final byte[] nameBytes = entry.name().getBytes(StandardCharsets.UTF_8);
    writeLittleEndianInt(archive, 0x02014b50);
    writeLittleEndianShort(archive, 20);
    writeLittleEndianShort(archive, 20);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianInt(archive, entry.crc32());
    writeLittleEndianInt(archive, entry.contents().length);
    writeLittleEndianInt(archive, entry.contents().length);
    writeLittleEndianShort(archive, nameBytes.length);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianInt(archive, 0);
    writeLittleEndianInt(archive, entry.localOffset());
    archive.writeBytes(nameBytes);
  }

  private static void writeEndOfCentralDirectory(
      final ByteArrayOutputStream archive, final int centralOffset, final int centralSize) {
    writeLittleEndianInt(archive, 0x06054b50);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 0);
    writeLittleEndianShort(archive, 2);
    writeLittleEndianShort(archive, 2);
    writeLittleEndianInt(archive, centralSize);
    writeLittleEndianInt(archive, centralOffset);
    writeLittleEndianShort(archive, 0);
  }

  private static void writeLittleEndianShort(final ByteArrayOutputStream output, final int value) {
    output.write(value & 0xff);
    output.write(value >>> 8 & 0xff);
  }

  private static void writeLittleEndianInt(final ByteArrayOutputStream output, final long value) {
    output.write((int) value & 0xff);
    output.write((int) (value >>> 8) & 0xff);
    output.write((int) (value >>> 16) & 0xff);
    output.write((int) (value >>> 24) & 0xff);
  }
}
