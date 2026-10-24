// WHY: Verifies ZIP-name indexing behavior with temporary archives and no external artifacts.

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises central-directory scanning with temporary ZIP archives. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
class JarIndexScannerTest {
  /** JUnit injects the per-test temporary directory into this package-private field. */
  @TempDir Path temporaryDirectory;

  /** Creates each test instance through this package-private constructor. */
  JarIndexScannerTest() {}

  @Test
  void indexesClassNamesWithoutInflatingAndExcludesModuleDescriptors() throws IOException {
    final Path jarPath = temporaryDirectory.resolve("fixture.jar");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jarPath))) {
      addEntry(zip, "org/example/Regular.class", new byte[] {1, 2, 3});
      addEntry(zip, "module-info.class", new byte[] {4});
      addEntry(zip, "META-INF/versions/17/module-info.class", new byte[] {5});
      addEntry(zip, "META-INF/versions/17/org/example/Versioned.class", new byte[] {6});
      addEntry(zip, "org/example/data.txt", new byte[] {7});
    }
    final ArtifactFileRef artifact = artifact(jarPath, "fixture");

    final ArtifactClassIndex index = new JarIndexScanner().scan(List.of(artifact));

    assertThat(index.classesFor(artifact))
        .containsExactlyInAnyOrder("org.example.Regular", "org.example.Versioned");
  }

  @Test
  void returnsAnEmptyIndexForNoArtifacts() throws IOException {
    assertThat(new JarIndexScanner().scan(List.of()).classesByArtifact()).isEmpty();
  }

  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void scansWhenClassEntryCompressedDataIsCorrupt() throws IOException {
    final Path jarPath = temporaryDirectory.resolve("corrupt-payload.jar");
    final byte[] payload = new byte[4096];
    java.util.Arrays.fill(payload, (byte) 'A');
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jarPath))) {
      addEntry(zip, "org/example/CorruptPayload.class", payload);
    }
    corruptCompressedData(jarPath, "org/example/CorruptPayload.class");
    final ArtifactFileRef artifact = artifact(jarPath, "corrupt-payload");

    try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
      assertThatThrownBy(
              () ->
                  zipFile
                      .getInputStream(zipFile.getEntry("org/example/CorruptPayload.class"))
                      .readAllBytes())
          .isInstanceOf(IOException.class);
    }
    assertThat(new JarIndexScanner().scan(List.of(artifact)).classesFor(artifact))
        .containsExactly("org.example.CorruptPayload");
  }

  @Test
  @SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.UseConcurrentHashMap"})
  void defensivelyCopiesConstructorInputsAndExposesImmutableCollections() {
    final ArtifactFileRef artifact = artifact(temporaryDirectory.resolve("unused.jar"), "unused");
    final Set<String> classes = new HashSet<>(Set.of("org.example.Original"));
    final Map<ArtifactFileRef, Set<String>> source = new LinkedHashMap<>();
    source.put(artifact, classes);
    final ArtifactClassIndex index = new ArtifactClassIndex(source);

    classes.add("org.example.Later");
    source.clear();

    assertThat(index.classesFor(artifact)).containsExactly("org.example.Original");
    assertThatThrownBy(() -> index.classesFor(artifact).add("org.example.Forbidden"))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> index.classesByArtifact().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> index.classesByArtifact().get(artifact).clear())
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void failsClearlyWhenAnArtifactCannotBeOpened() throws IOException {
    final Path missingJar = temporaryDirectory.resolve("missing.jar");
    final ArtifactFileRef artifact = artifact(missingJar, "missing");

    assertThatThrownBy(() -> new JarIndexScanner().scan(List.of(artifact)))
        .isInstanceOf(IOException.class);
  }

  private static ArtifactFileRef artifact(final Path path, final String name) {
    return new ArtifactFileRef(ArtifactCoordinate.of("test", name, "1"), path, 0, 0);
  }

  private static void addEntry(final ZipOutputStream zip, final String name, final byte[] content)
      throws IOException {
    zip.putNextEntry(new ZipEntry(name));
    zip.write(content);
    zip.closeEntry();
  }

  private static void corruptCompressedData(final Path jarPath, final String entryName)
      throws IOException {
    final long compressedSize;
    try (ZipFile zipFile = new ZipFile(jarPath.toFile())) {
      compressedSize = zipFile.getEntry(entryName).getCompressedSize();
    }
    final byte[] archive = Files.readAllBytes(jarPath);
    final ByteBuffer header = ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN);
    final int nameLength = Short.toUnsignedInt(header.getShort(26));
    final int extraLength = Short.toUnsignedInt(header.getShort(28));
    final int compressedDataOffset = 30 + nameLength + extraLength;
    java.util.Arrays.fill(
        archive,
        compressedDataOffset,
        compressedDataOffset + Math.toIntExact(compressedSize),
        (byte) 0xff);
    Files.write(jarPath, archive);
  }
}
