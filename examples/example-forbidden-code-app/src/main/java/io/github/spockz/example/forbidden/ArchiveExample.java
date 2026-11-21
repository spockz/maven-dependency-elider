// WHY: Keeps the same harmless Commons Compress operation in all policy variants.

package io.github.spockz.example.forbidden;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;

/** Supplies a benign ZIP entry shared by the fixture entry points. */
final class ArchiveExample {
  private ArchiveExample() {}

  /* package */ static ZipArchiveEntry entry() {
    return new ZipArchiveEntry("message.txt");
  }
}
