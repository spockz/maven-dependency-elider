/* WHY: Builds the exact CNA source claims and JAR entry cases used by corroboration tests. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Creates local CVE, OSV and MRJAR inputs without relying on external services. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
final class MavenCorroboratedSourceArchiveFixtures {
  /** Native JSON writer for variable CNA claim fixtures. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Manifest version required for generated test JARs. */
  private static final String MANIFEST_VERSION = "1.0";

  /** CVE selected for the typed structured-source fixture. */
  static final String CVE_ID = "CVE-2025-12345";

  /** Maven group used by the affected package. */
  static final String GROUP_ID = "org.example";

  /** Maven artifact used by the affected package. */
  static final String ARTIFACT_ID = "demo";

  /** Shared affected field key and exact CNA version status. */
  private static final String AFFECTED = "affected";

  /** Maven package URL used by the matched source claim. */
  private static final String MAVEN_PACKAGE_URL = "pkg:maven/" + GROUP_ID + "/" + ARTIFACT_ID;

  /** Exact version asserted by the CNA affected product. */
  static final String VERSION = "1.0";

  /** Source timestamp carried by the deterministic OSV test record. */
  private static final String SOURCE_MODIFIED = "2026-10-31T00:00:00Z";

  /** CNA programFiles value used by the SourceFile fixture. */
  static final String PROGRAM_FILE = "src/main/java/org/example/Outer.java";

  /** SourceFile attribute shared by matching Java class entries. */
  static final String SOURCE_FILE_ATTRIBUTE = "Outer.java";

  private MavenCorroboratedSourceArchiveFixtures() {}

  static Path writeCveRecord(final Path directory) throws IOException {
    final Path record = directory.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(record.getParent());
    final ObjectNode root = JSON.createObjectNode();
    root.putObject("cveMetadata").put("cveId", CVE_ID).put("state", "PUBLISHED");
    final ArrayNode affected = root.putObject("containers").putObject("cna").putArray(AFFECTED);
    affected.add(cnaAffected("other", List.of("src/main/java/org/example/Outer.java")));
    affected.add(
        cnaAffected(
            ARTIFACT_ID,
            List.of(
                "src/main/java/org/example/Outer.java", "src/main/kotlin/org/example/Thing.kt")));
    JSON.writeValue(record.toFile(), root);
    return record;
  }

  private static ObjectNode cnaAffected(final String packageName, final List<String> programFiles) {
    final ObjectNode entry = JSON.createObjectNode();
    entry.put("vendor", "Example");
    entry.put("product", ARTIFACT_ID);
    entry.put("packageURL", "pkg:maven/" + GROUP_ID + "/" + packageName);
    entry.putArray("versions").addObject().put("version", VERSION).put("status", AFFECTED);
    final ArrayNode files = entry.putArray("programFiles");
    programFiles.forEach(files::add);
    return entry;
  }

  static Path writeUnmatchedFileOnlyRecord(final Path directory) throws IOException {
    return writeSourceRecord(directory, false, null);
  }

  static Path writeRoutineOnlyRecord(final Path directory, final String defaultStatus)
      throws IOException {
    return writeSourceRecord(directory, true, defaultStatus);
  }

  static Path writeCorrespondenceRecord(
      final Path directory, final List<String> programFiles, final List<String> routineNames)
      throws IOException {
    final Path record = directory.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(record.getParent());
    final ObjectNode root = JSON.createObjectNode();
    root.putObject("cveMetadata").put("cveId", CVE_ID).put("state", "PUBLISHED");
    final ObjectNode entry =
        root.putObject("containers")
            .putObject("cna")
            .putArray(AFFECTED)
            .addObject()
            .put("vendor", "Example")
            .put("product", ARTIFACT_ID)
            .put("packageURL", MAVEN_PACKAGE_URL);
    entry.putArray("versions").addObject().put("version", VERSION).put("status", AFFECTED);
    programFiles.forEach(value -> entry.withArray("programFiles").add(value));
    routineNames.forEach(
        value -> entry.withArray("programRoutines").addObject().put("name", value));
    JSON.writeValue(record.toFile(), root);
    return record;
  }

  private static Path writeSourceRecord(
      final Path directory, final boolean routineOnly, final String defaultStatus)
      throws IOException {
    final Path record = directory.resolve("cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(record.getParent());
    final ObjectNode root = JSON.createObjectNode();
    root.putObject("cveMetadata").put("cveId", CVE_ID).put("state", "PUBLISHED");
    final ObjectNode entry =
        root.putObject("containers")
            .putObject("cna")
            .putArray(AFFECTED)
            .addObject()
            .put("vendor", "Example")
            .put("product", ARTIFACT_ID)
            .put("packageURL", MAVEN_PACKAGE_URL);
    if (defaultStatus == null) {
      final ObjectNode version = entry.putArray("versions").addObject();
      version.put("version", VERSION).put("status", AFFECTED);
      if (routineOnly) {
        version.put("versionType", "semver").put("lessThan", "2.0");
      }
    } else {
      entry.put("defaultStatus", defaultStatus);
    }
    if (routineOnly) {
      entry.putArray("programRoutines").addObject().put("name", "parse");
    } else {
      entry.putArray("programFiles").add("src/main/java/org/elsewhere/Outer.java");
    }
    JSON.writeValue(record.toFile(), root);
    return record;
  }

  static byte[] osvSnapshot() throws IOException {
    final ObjectNode root = JSON.createObjectNode();
    root.put("id", "GHSA-source");
    root.put("modified", SOURCE_MODIFIED);
    root.putArray("aliases").add(CVE_ID);
    final ObjectNode affected = root.putArray(AFFECTED).addObject();
    affected
        .putObject("package")
        .put("ecosystem", "Maven")
        .put("name", GROUP_ID + ":" + ARTIFACT_ID);
    final ObjectNode range = affected.putArray("ranges").addObject().put("type", "ECOSYSTEM");
    range.putArray("events").addObject().put("introduced", VERSION);
    range.withArray("events").addObject().put("fixed", "2.0");
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.putNextEntry(new ZipEntry("GHSA-source.json"));
      zip.write(JSON.writeValueAsBytes(root));
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  static Path writeOriginalJar(final Path archive, final boolean mutationMarker)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, MANIFEST_VERSION);
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
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, MANIFEST_VERSION);
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
