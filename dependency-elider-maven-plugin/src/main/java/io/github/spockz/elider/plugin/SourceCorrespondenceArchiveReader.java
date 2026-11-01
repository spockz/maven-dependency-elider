// WHY: Validates archive structure while retaining only the source bytes and class hashes needed
// later.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Reads ordinary binary or sources JARs and rejects unsupported physical layouts. */
final class SourceCorrespondenceArchiveReader {
  /** File suffix retained as a compilable source unit. */
  private static final String JAVA_SUFFIX = ".java";

  /** File suffix included in the complete original JAR inventory. */
  private static final String CLASS_SUFFIX = ".class";

  /** Bounds path bookkeeping for untrusted archives. */
  private static final int MAX_ARCHIVE_ENTRIES = 100_000;

  /** Bounds total decompressed archive data. */
  private static final long MAX_ARCHIVE_BYTES = 1024L * 1024 * 1024;

  private SourceCorrespondenceArchiveReader() {}

  /* default */ static SourceCorrespondenceArchive readOriginal(final Path path)
      throws IOException {
    return read(path, false);
  }

  /* default */ static SourceCorrespondenceArchive readSources(final Path path) throws IOException {
    return read(path, true);
  }

  private static SourceCorrespondenceArchive read(final Path path, final boolean sources)
      throws IOException {
    final ReadContents contents;
    try (JarFile jar = new JarFile(path.toFile(), true)) {
      if (jar.size() > MAX_ARCHIVE_ENTRIES) {
        throw new IOException("Archive contains too many physical entries: " + path);
      }
      SourceArchiveLayout.requireSupportedManifest(jar, path);
      contents = readEntries(jar, path, sources);
    } catch (final SecurityException exception) {
      throw new IOException("Archive signature validation failed: " + path, exception);
    }
    if (!sources && contents.classDigests().isEmpty()) {
      throw new IOException("Original JAR contains no physical class entries");
    }
    final List<SourceBuildCorrespondence.ClassEntry> classes =
        contents.classDigests().entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .map(
                entry -> new SourceBuildCorrespondence.ClassEntry(entry.getKey(), entry.getValue()))
            .toList();
    return new SourceCorrespondenceArchive(
        ArtifactFileDigest.sha256(path),
        contents.sourceContents(),
        classes,
        contents.sourceEntries().stream().sorted().toList());
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // These maps are confined to one archive read.
  private static ReadContents readEntries(final JarFile jar, final Path path, final boolean sources)
      throws IOException {
    final Map<String, byte[]> sourceContents = new HashMap<>();
    final Map<String, String> classDigests = new HashMap<>();
    final List<String> sourceEntries = new ArrayList<>();
    final Set<String> physicalEntries = new HashSet<>();
    long totalBytes = 0;
    final Enumeration<JarEntry> entries = jar.entries();
    while (entries.hasMoreElements()) {
      final JarEntry entry = entries.nextElement();
      if (entry.isDirectory()) {
        continue;
      }
      totalBytes =
          readEntry(
              jar,
              entry,
              path,
              sources,
              totalBytes,
              physicalEntries,
              sourceContents,
              sourceEntries,
              classDigests);
    }
    return new ReadContents(sourceContents, sourceEntries, classDigests);
  }

  private static long readEntry(
      final JarFile jar,
      final JarEntry entry,
      final Path path,
      final boolean sources,
      final long totalBytes,
      final Set<String> physicalEntries,
      final Map<String, byte[]> sourceContents,
      final List<String> sourceEntries,
      final Map<String, String> classDigests)
      throws IOException {
    final String name = entry.getName();
    SourceArchiveLayout.requireSafePath(name, path);
    SourceArchiveLayout.requireNonVersioned(name);
    if (!physicalEntries.add(name)) {
      throw new IOException("Duplicate archive entry: " + name);
    }
    final boolean javaSource = sources && name.endsWith(JAVA_SUFFIX);
    if (sources && isUnsupportedSource(name)) {
      throw new IOException("Unsupported source language in sources archive: " + name);
    }
    final SourceArchiveEntryReader.Content content =
        SourceArchiveEntryReader.read(jar, entry, javaSource);
    final long updatedBytes = totalBytes + content.size();
    if (updatedBytes > MAX_ARCHIVE_BYTES) {
      throw new IOException("Archive uncompressed content exceeds the supported limit: " + path);
    }
    if (sources) {
      addSource(name, javaSource, content, sourceContents, sourceEntries);
    } else {
      addBinary(name, content, classDigests);
    }
    return updatedBytes;
  }

  private record ReadContents(
      Map<String, byte[]> sourceContents,
      List<String> sourceEntries,
      Map<String, String> classDigests) {}

  private static void addSource(
      final String name,
      final boolean javaSource,
      final SourceArchiveEntryReader.Content content,
      final Map<String, byte[]> sourceContents,
      final List<String> sourceEntries)
      throws IOException {
    if (name.endsWith(CLASS_SUFFIX)) {
      throw new IOException("Binary class entries in sources archive are unsupported: " + name);
    }
    if (!javaSource) {
      return;
    }
    if ("module-info.java".equals(name) || name.endsWith("/module-info.java")) {
      throw new IOException("Module descriptors are unsupported: " + name);
    }
    final byte[] bytes =
        content
            .bytes()
            .orElseThrow(() -> new IOException("Source bytes were not retained: " + name));
    decodeUtf8(bytes, name);
    sourceContents.put(name, bytes);
    sourceEntries.add(name);
  }

  private static void addBinary(
      final String name,
      final SourceArchiveEntryReader.Content content,
      final Map<String, String> classDigests)
      throws IOException {
    if (name.endsWith(CLASS_SUFFIX)) {
      if ("module-info.class".equals(name) || name.endsWith("/module-info.class")) {
        throw new IOException("Module descriptors are unsupported: " + name);
      }
      classDigests.put(name, content.sha256());
    }
  }

  private static boolean isUnsupportedSource(final String name) {
    return List.of(".kt", ".kts", ".scala", ".groovy").stream().anyMatch(name::endsWith);
  }

  private static String decodeUtf8(final byte[] bytes, final String path) throws IOException {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (final CharacterCodingException exception) {
      throw new IOException("Source file is not valid UTF-8: " + path, exception);
    }
  }
}
