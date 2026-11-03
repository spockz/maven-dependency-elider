// WHY: Builds narrow malformed source and trim archives for path-identity proof regressions.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/** Creates exact compiled archives with adversarial source path associations. */
final class MavenAdversarialSourceArchiveFixtures {
  /** One local record and one central record contain the repeated directory name. */
  private static final int DIRECTORY_NAME_RECORD_COUNT = 2;

  private MavenAdversarialSourceArchiveFixtures() {}

  /* default */ static Path copyJarKeepingEntry(
      final Path original, final Path trimmed, final String retainedEntry) throws IOException {
    try (JarFile input = new JarFile(original.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(trimmed))) {
      final JarEntry entry = input.getJarEntry(retainedEntry);
      if (entry == null) {
        throw new IOException("Required source-output fixture entry is missing: " + retainedEntry);
      }
      output.putNextEntry(new JarEntry(entry.getName()));
      try (InputStream content = input.getInputStream(entry)) {
        content.transferTo(output);
      }
      output.closeEntry();
    }
    return trimmed;
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* default */ static void addResourceWhilePreservingJarEntries(final Path archive)
      throws IOException {
    try (JarFile existing = new JarFile(archive.toFile())) {
      if (existing.getEntry("META-INF/revalidation-marker.txt") != null) {
        return;
      }
    }
    final Path rewritten = archive.resolveSibling(archive.getFileName() + ".rewritten");
    try (JarFile input = new JarFile(archive.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(rewritten))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        // A fresh JarEntry is required because JarOutputStream consumes each instance.
        output.putNextEntry(new JarEntry(entry.getName()));
        try (InputStream content = input.getInputStream(entry)) {
          content.transferTo(output);
        }
        output.closeEntry();
      }
      addEntry(output, "META-INF/revalidation-marker.txt", new byte[] {1, 2, 3});
    }
    Files.move(rewritten, archive, StandardCopyOption.REPLACE_EXISTING);
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* default */ static void addDuplicateDirectoryEntry(final Path archive) throws IOException {
    final Path rewritten = archive.resolveSibling(archive.getFileName() + ".duplicate-directory");
    try (JarFile input = new JarFile(archive.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(rewritten))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        output.putNextEntry(new JarEntry(entry.getName()));
        try (InputStream contents = input.getInputStream(entry)) {
          contents.transferTo(output);
        }
        output.closeEntry();
      }
      output.putNextEntry(new JarEntry("proofdup/"));
      output.closeEntry();
      output.putNextEntry(new JarEntry("proofalt/"));
      output.closeEntry();
    }
    replaceDirectoryName(rewritten, "proofalt/", "proofdup/");
    Files.move(rewritten, archive, StandardCopyOption.REPLACE_EXISTING);
  }

  private static void replaceDirectoryName(
      final Path archive, final String originalName, final String replacementName)
      throws IOException {
    final byte[] bytes = Files.readAllBytes(archive);
    final byte[] original = originalName.getBytes(StandardCharsets.UTF_8);
    final byte[] replacement = replacementName.getBytes(StandardCharsets.UTF_8);
    if (original.length != replacement.length) {
      throw new IOException("Duplicate directory fixture names must have equal length");
    }
    int matchCount = 0;
    int offset = 0;
    while (offset <= bytes.length - original.length) {
      if (matchesAt(bytes, original, offset)) {
        System.arraycopy(replacement, 0, bytes, offset, replacement.length);
        matchCount++;
        offset += original.length;
      } else {
        offset++;
      }
    }
    if (matchCount != DIRECTORY_NAME_RECORD_COUNT) {
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

  private static void addEntry(final JarOutputStream output, final String name, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }
}
