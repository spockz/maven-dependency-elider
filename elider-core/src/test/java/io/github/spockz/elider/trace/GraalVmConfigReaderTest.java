/* WHY: Verifies GraalVM reflection config parsing and failures using temporary local JSON files. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers GraalVM reflection configuration input. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class GraalVmConfigReaderTest {
  /** Supplies isolated paths for each test. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  GraalVmConfigReaderTest() {}

  @Test
  void readsDescriptorNamesIntoNormalizedTrace() throws IOException {
    final Path config = tempDir.resolve("reflect-config.json");
    Files.writeString(
        config,
        "[{\"name\":\"org.example.Widget\",\"allDeclaredMethods\":true},"
            + "{\"name\":\"org.example.Other\"}]");

    final TraceData result = new GraalVmConfigReader().read(config);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder("org.example.Widget", "org.example.Other");
    assertThat(result.loadedClassesSlashFormat()).contains("org/example/Widget");
  }

  @Test
  void rejectsMalformedOrUnsupportedConfigurations() throws IOException {
    final Path malformed = tempDir.resolve("malformed.json");
    final Path invalidName = tempDir.resolve("invalid-name.json");
    final Path trailingRoot = tempDir.resolve("trailing.json");
    final Path arrayName = tempDir.resolve("array-name.json");
    final Path duplicateName = tempDir.resolve("duplicate.json");
    Files.writeString(malformed, "[{\"name\":42}]");
    Files.writeString(invalidName, "[{\"name\":\"not a class\"}]");
    Files.writeString(trailingRoot, "[{\"name\":\"org.example.Valid\"}] []");
    Files.writeString(arrayName, "[{\"name\":\"[Lorg.example.Widget;\"}]");
    Files.writeString(
        duplicateName, "[{\"name\":\"org.example.First\",\"name\":\"org.example.Second\"}]");
    final GraalVmConfigReader reader = new GraalVmConfigReader();

    assertThatIOException().isThrownBy(() -> reader.read(malformed));
    assertThatIOException().isThrownBy(() -> reader.read(invalidName));
    assertThatIOException().isThrownBy(() -> reader.read(trailingRoot));
    assertThatIOException().isThrownBy(() -> reader.read(arrayName));
    assertThatIOException().isThrownBy(() -> reader.read(duplicateName));
    assertThatIOException().isThrownBy(() -> reader.read(tempDir.resolve("classes.log")));
  }

  @Test
  void propagatesUnreadableFiles() {
    final Path missing = tempDir.resolve("missing.json");

    assertThatIOException().isThrownBy(() -> new GraalVmConfigReader().read(missing));
  }
}
