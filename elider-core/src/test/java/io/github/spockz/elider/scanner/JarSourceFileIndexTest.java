/* WHY: Checks that classfile source names remain tied to physical JAR entries and bytes. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises SourceFile indexing from generated local archives. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class JarSourceFileIndexTest {

  /** Source name shared by generated class files in the duplicate-basename fixture. */
  private static final String OUTER_SOURCE = "Outer.java";

  /** Archive name reused by scenarios that verify MRJAR behavior. */
  private static final String MULTI_RELEASE_ARCHIVE = "multi-release.jar";

  /** Temporary workspace isolates generated archive scenarios. */
  @TempDir private Path tempDir;

  @Test
  void retainsPhysicalEntriesForEveryClassVariant() throws IOException {
    final Path archive = tempDir.resolve(MULTI_RELEASE_ARCHIVE);
    JarSourceFileFixtures.writeArchive(archive, true, OUTER_SOURCE);
    final JarSourceFileIndex index = JarSourceFileIndex.read(archive);

    assertThat(index.classFiles())
        .extracting(JarSourceFileIndex.ClassSourceFile::physicalJarEntry)
        .containsExactly(
            "META-INF/versions/17/org/example/Outer.class",
            "org/example/Helper.class",
            "org/example/Outer$1.class",
            "org/example/Outer.class",
            "org/other/Outer.class",
            "org/other/WithoutSource.class");
  }

  @Test
  void retainsSourceAttributesAndMultiReleaseTierForVersionedClass() throws IOException {
    final Path archive = tempDir.resolve(MULTI_RELEASE_ARCHIVE);
    JarSourceFileFixtures.writeArchive(archive, true, OUTER_SOURCE);
    final JarSourceFileIndex index = JarSourceFileIndex.read(archive);

    assertThat(index.classFiles())
        .filteredOn(value -> value.physicalJarEntry().startsWith("META-INF/versions/"))
        .extracting(
            JarSourceFileIndex.ClassSourceFile::classEntry,
            JarSourceFileIndex.ClassSourceFile::multiReleaseTier,
            JarSourceFileIndex.ClassSourceFile::sourceFile)
        .containsExactly(tuple("org.example.Outer", 17, OUTER_SOURCE));
  }

  @Test
  void retainsClassFilesWithoutSourceAttributesAsUnresolved() throws IOException {
    final Path archive = tempDir.resolve(MULTI_RELEASE_ARCHIVE);
    JarSourceFileFixtures.writeArchive(archive, true, OUTER_SOURCE);
    final JarSourceFileIndex index = JarSourceFileIndex.read(archive);

    assertThat(index.classFiles())
        .filteredOn(value -> "org/other/WithoutSource.class".equals(value.physicalJarEntry()))
        .extracting(JarSourceFileIndex.ClassSourceFile::sourceFile)
        .containsExactly((String) null);
  }

  @Test
  void recordsTheArchiveDigest() throws IOException, NoSuchAlgorithmException {
    final Path archive = tempDir.resolve(MULTI_RELEASE_ARCHIVE);
    JarSourceFileFixtures.writeArchive(archive, true, OUTER_SOURCE);
    final String expectedDigest =
        HexFormat.of()
            .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(archive)));

    assertThat(JarSourceFileIndex.read(archive).archiveSha256()).isEqualTo(expectedDigest);
  }

  @Test
  void doesNotTreatVersionedEntriesAsMultiReleaseWithoutManifestOptIn() throws IOException {
    final Path archive = tempDir.resolve("ordinary.jar");
    JarSourceFileFixtures.writeArchive(archive, false, OUTER_SOURCE);

    assertThat(JarSourceFileIndex.read(archive).classFiles())
        .noneMatch(value -> value.physicalJarEntry().startsWith("META-INF/versions/"));
  }

  @Test
  void reportsTheCurrentArchiveDigestAfterArtifactBytesChange() throws IOException {
    final Path archive = tempDir.resolve("mutable.jar");
    JarSourceFileFixtures.writeArchive(archive, false, OUTER_SOURCE);
    final String before = JarSourceFileIndex.read(archive).archiveSha256();
    JarSourceFileFixtures.writeArchive(archive, false, "Changed.java");
    final JarSourceFileIndex changed = JarSourceFileIndex.read(archive);

    assertAll(
        "archive mutation updates the digest and indexed SourceFile value",
        () -> assertThat(changed.archiveSha256()).isNotEqualTo(before),
        () ->
            assertThat(sourceFileFor(changed, "org/example/Outer.class"))
                .isEqualTo("Changed.java"));
  }

  @Test
  void rejectsNonCanonicalAndUnsupportedMultiReleaseTiers() {
    assertAll(
        "MRJAR class tier must be canonical decimal and at least 9",
        () -> assertInvalidTier("017"),
        () -> assertInvalidTier("+17"),
        () -> assertInvalidTier("8"));
  }

  @Test
  void rejectsDuplicatePhysicalZipEntryNames() throws IOException {
    final Path archive = tempDir.resolve("duplicate-entry.jar");
    DuplicateZipEntryArchiveFixture.write(archive);
    final List<String> entryNames;
    try (ZipFile zip = new ZipFile(archive.toFile())) {
      entryNames = Collections.list(zip.entries()).stream().map(ZipEntry::getName).toList();
    }

    assertAll(
        "the ZIP contains duplicate physical records and the scanner rejects their name",
        () -> assertThat(entryNames).containsExactly("duplicate.txt", "duplicate.txt"),
        () ->
            assertThatThrownBy(() -> JarSourceFileIndex.read(archive))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("duplicate physical ZIP entry"));
  }

  private void assertInvalidTier(final String tierText) throws IOException {
    final Path archive = tempDir.resolve("invalid-tier-" + tierText + ".jar");
    JarSourceFileFixtures.writeArchiveWithVersionEntry(archive, tierText);

    assertThatThrownBy(() -> JarSourceFileIndex.read(archive))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("multi-release class entry version");
  }

  private static String sourceFileFor(final JarSourceFileIndex index, final String physicalEntry) {
    return index.classFiles().stream()
        .filter(value -> physicalEntry.equals(value.physicalJarEntry()))
        .map(JarSourceFileIndex.ClassSourceFile::sourceFile)
        .findFirst()
        .orElse(null);
  }
}
