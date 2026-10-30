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

  /** Writes one ZIP entry. */
  private static void writeEntry(
      final JarOutputStream output, final String name, final byte[] content) throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(content);
    output.closeEntry();
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
