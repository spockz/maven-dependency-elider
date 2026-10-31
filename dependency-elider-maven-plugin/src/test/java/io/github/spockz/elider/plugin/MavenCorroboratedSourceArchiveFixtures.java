/* WHY: Builds the exact CNA source claims and JAR entry cases used by corroboration tests. */

package io.github.spockz.elider.plugin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Creates local CVE, OSV and MRJAR inputs without relying on external services. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenCorroboratedSourceArchiveFixtures {
  /** CVE selected for the typed structured-source fixture. */
  static final String CVE_ID = "CVE-2025-12345";

  /** Maven group used by the affected package. */
  static final String GROUP_ID = "org.example";

  /** Maven artifact used by the affected package. */
  static final String ARTIFACT_ID = "demo";

  /** Exact version asserted by the CNA affected product. */
  static final String VERSION = "1.0";

  /** CNA programFiles value used by the SourceFile fixture. */
  static final String PROGRAM_FILE = "src/main/java/org/example/Outer.java";

  /** SourceFile attribute shared by matching Java class entries. */
  static final String SOURCE_FILE_ATTRIBUTE = "Outer.java";

  private MavenCorroboratedSourceArchiveFixtures() {}

  static Path writeCveRecord(final Path directory) throws IOException {
    final Path record = directory.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(record.getParent());
    Files.writeString(
        record,
        """
        {
          "containers":{"cna":{"affected":[
            {
              "vendor":"Example",
              "product":"demo",
              "packageURL":"pkg:maven/org.example/other",
              "versions":[{"version":"1.0","status":"affected"}],
              "programFiles":["src/main/java/org/example/Outer.java"]
            },
            {
              "vendor":"Example",
              "product":"demo",
              "packageURL":"pkg:maven/org.example/demo",
              "versions":[{"version":"1.0","status":"affected"}],
              "programFiles":["src/main/java/org/example/Outer.java","src/main/kotlin/org/example/Thing.kt"]
            }
          ]}}
        }
        """);
    return record;
  }

  static byte[] osvSnapshot() throws IOException {
    final String record =
        """
        {"id":"GHSA-source","aliases":["CVE-2025-12345"],"affected":[{"package":{"ecosystem":"Maven","name":"org.example:demo"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"2.0"}]}]}]}
        """;
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.putNextEntry(new ZipEntry("GHSA-source.json"));
      zip.write(record.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  static Path writeOriginalJar(final Path archive, final boolean mutationMarker)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      zip.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
      manifest.write(zip);
      zip.closeEntry();
      addClass(zip, "org/example/Outer.class", "org/example/Outer", SOURCE_FILE_ATTRIBUTE);
      addClass(zip, "org/example/Helper.class", "org/example/Helper", SOURCE_FILE_ATTRIBUTE);
      addClass(zip, "org/example/Outer$1.class", "org/example/Outer$1", SOURCE_FILE_ATTRIBUTE);
      addClass(
          zip, "org/example/package-info.class", "org/example/package-info", SOURCE_FILE_ATTRIBUTE);
      addClass(
          zip,
          "META-INF/versions/17/org/example/Outer.class",
          "org/example/Outer",
          SOURCE_FILE_ATTRIBUTE);
      addClass(zip, "org/other/Outer.class", "org/other/Outer", SOURCE_FILE_ATTRIBUTE);
      addClass(zip, "org/example/NoSource.class", "org/example/NoSource", null);
      addClass(zip, "org/example/Thing.class", "org/example/Thing", "Thing.kt");
      if (mutationMarker) {
        zip.putNextEntry(new ZipEntry("META-INF/source-review-mutation.txt"));
        zip.write(new byte[] {1});
        zip.closeEntry();
      }
    }
    return archive;
  }

  static void writeTrimmedJar(final Path path) throws IOException {
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(path))) {
      zip.putNextEntry(new ZipEntry("empty.txt"));
      zip.write(new byte[] {1});
      zip.closeEntry();
    }
  }

  static void writeNonCanonicalVersionArchive(final Path archive) throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
      zip.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
      manifest.write(zip);
      zip.closeEntry();
      addClass(
          zip,
          "META-INF/versions/017/org/example/Outer.class",
          "org/example/Outer",
          SOURCE_FILE_ATTRIBUTE);
    }
  }

  private static void addClass(
      final ZipOutputStream zip,
      final String entry,
      final String internalName,
      final String sourceFile)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    if (sourceFile != null) {
      writer.visitSource(sourceFile, null);
    }
    writer.visitEnd();
    zip.putNextEntry(new ZipEntry(entry));
    zip.write(writer.toByteArray());
    zip.closeEntry();
  }
}
