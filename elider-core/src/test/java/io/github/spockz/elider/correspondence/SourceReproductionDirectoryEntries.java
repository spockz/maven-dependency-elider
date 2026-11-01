// WHY: Adds directory records to JAR fixtures, including duplicates normal writers refuse.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Rewrites JAR fixtures with directory records. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SourceReproductionDirectoryEntries {
  /** Both ZIP records for the directory name must be rewritten. */
  private static final int DIRECTORY_NAME_RECORD_COUNT = 2;

  private SourceReproductionDirectoryEntries() {}

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  // Each ZIP record requires a fresh mutable JarEntry instance.
  static void add(final Path archive, final String... directoryNames) throws IOException {
    final Path replacement = archive.resolveSibling(archive.getFileName() + ".directories");
    try (ZipFile input = new ZipFile(archive.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(replacement))) {
      final Enumeration<? extends ZipEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        output.putNextEntry(new JarEntry(entry.getName()));
        try (InputStream contents = input.getInputStream(entry)) {
          contents.transferTo(output);
        }
        output.closeEntry();
      }
      for (final String directoryName : directoryNames) {
        output.putNextEntry(new JarEntry(directoryName));
        output.closeEntry();
      }
    }
    Files.move(replacement, archive, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
  }

  static void addDuplicate(final Path archive) throws IOException {
    final String firstName = "cachedup/";
    final String secondName = "cachealt/";
    add(archive, firstName, secondName);
    replaceRepeatedName(archive, secondName, firstName);
  }

  private static void replaceRepeatedName(
      final Path archive, final String originalName, final String replacementName)
      throws IOException {
    final byte[] bytes = Files.readAllBytes(archive);
    final byte[] original = originalName.getBytes(StandardCharsets.UTF_8);
    final byte[] replacement = replacementName.getBytes(StandardCharsets.UTF_8);
    if (original.length != replacement.length) {
      throw new IOException("Duplicate ZIP fixture names must have equal length");
    }
    int matches = 0;
    int offset = 0;
    while (offset <= bytes.length - original.length) {
      if (matchesAt(bytes, original, offset)) {
        System.arraycopy(replacement, 0, bytes, offset, replacement.length);
        matches++;
        offset += original.length;
      } else {
        offset++;
      }
    }
    if (matches != DIRECTORY_NAME_RECORD_COUNT) {
      throw new IOException("Expected one local and one central directory name record");
    }
    Files.write(archive, bytes);
  }

  private static boolean matchesAt(final byte[] bytes, final byte[] expected, final int offset) {
    for (int index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) {
        return false;
      }
    }
    return true;
  }
}
