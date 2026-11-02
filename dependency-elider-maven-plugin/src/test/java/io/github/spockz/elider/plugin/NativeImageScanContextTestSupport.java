/* WHY: Shares tiny archive and artifact fixtures across resource-context tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/** Reusable archive inputs for classpath resource behavior tests. */
/* package */ final class NativeImageScanContextTestSupport {
  /** Local-header and central-directory records for one ZIP filename. */
  private static final int ZIP_ENTRY_NAME_RECORD_COUNT = 2;

  /* package */
  /** Properties entry used by native-image option fixtures. */
  static final String PROPERTIES_ENTRY = "META-INF/native-image/test/native-image.properties";

  /* package */
  /** Coordinate used for declaration archives. */
  static final String DECLARING_ARTIFACT = "declaring";

  /* package */
  /** Descriptor-relative resource used to prove archive-local lookup. */
  static final String LOCAL_RESOURCE = "META-INF/native-image/test/local.payload";

  /* package */
  /** Invalid JSON used to prove malformed copies fail. */
  static final String MALFORMED_JSON = "not-json";

  /** Creates this static fixture holder. */
  private NativeImageScanContextTestSupport() {
    throw new AssertionError("static test fixture holder");
  }

  /** Writes a small archive from alternating entry names and bodies. */
  /* package */ static Path jar(final Path directory, final String name, final String... entries)
      throws IOException {
    final Path path = directory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (int index = 0; index < entries.length; index += 2) {
        writeEntry(output, entries[index], entries[index + 1].getBytes(StandardCharsets.UTF_8));
      }
    }
    return path;
  }

  /* package */ static Path duplicateEntryJar(
      final Path directory,
      final String name,
      final String resourceName,
      final String firstBody,
      final String alternateName,
      final String secondBody)
      throws IOException {
    final byte[] alternate = alternateName.getBytes(StandardCharsets.UTF_8);
    final byte[] replacement = resourceName.getBytes(StandardCharsets.UTF_8);
    if (replacement.length != alternate.length) {
      throw new IllegalArgumentException("ZIP entry names must have equal UTF-8 lengths");
    }
    final Path path = jar(directory, name, resourceName, firstBody, alternateName, secondBody);
    final byte[] archive = Files.readAllBytes(path);
    int matchCount = 0;
    int offset = 0;
    while (offset <= archive.length - alternate.length) {
      if (matchesAt(archive, alternate, offset)) {
        System.arraycopy(replacement, 0, archive, offset, replacement.length);
        matchCount++;
        offset += alternate.length;
      } else {
        offset++;
      }
    }
    if (matchCount != ZIP_ENTRY_NAME_RECORD_COUNT) {
      throw new IOException("Expected one local and one central ZIP entry name record");
    }
    Files.write(path, archive);
    return path;
  }

  /** Writes one ZIP entry. */
  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] content) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(content);
    output.closeEntry();
  }

  private static boolean matchesAt(final byte[] bytes, final byte[] expected, final int offset) {
    for (int index = 0; index < expected.length; index++) {
      if (bytes[offset + index] != expected[index]) {
        return false;
      }
    }
    return true;
  }

  /** Returns paired fixture names and bodies. */
  /* package */ static String[] entries(final String... values) {
    return values;
  }

  /** Builds the standalone reflection shape used by resource pointer tests. */
  /* package */ static String reflection(final String className) {
    return "[{\"name\":\"" + className + "\"}]";
  }

  /** Binds a candidate archive to a stable coordinate for deterministic indexing. */
  /* package */ static ArtifactFileRef candidate(final String artifact, final Path path)
      throws IOException {
    return ArtifactFileRef.fromPath(ArtifactCoordinate.of("org.example", artifact, "1.0"), path);
  }
}
