/* WHY: Verifies composite trace merging and fail-fast handling for empty or unsupported inputs. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers multi-file composition across supported trace formats. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class CompositeTraceReaderTest {
  /** Supplies isolated paths for each test. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  CompositeTraceReaderTest() {}

  @Test
  void mergesExplicitTraceFiles() throws IOException {
    final Path log = tempDir.resolve("classes.log");
    final Path classList = tempDir.resolve("classes.lst");
    Files.writeString(log, "[info][class,load] org.example.FromLog source: file:/app.jar\n");
    Files.writeString(classList, "org/example/FromCds\n");

    final TraceData result = new CompositeTraceReader().readAll(List.of(log, classList));

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder("org.example.FromLog", "org.example.FromCds");
  }

  @Test
  void rejectsEmptyAggregateButAllowsEmptySourceWhenAnotherContributes() throws IOException {
    final Path emptyConfig = tempDir.resolve("empty.json");
    final Path log = tempDir.resolve("classes.log");
    Files.writeString(emptyConfig, "[]");
    Files.writeString(log, "[info][class,load] org.example.Observed source: file:/app.jar\n");
    final CompositeTraceReader reader = new CompositeTraceReader();

    assertThatIOException().isThrownBy(() -> reader.readAll(List.of(emptyConfig)));
    assertThat(reader.readAll(List.of(emptyConfig, log)).loadedClassesDotFormat())
        .containsExactly("org.example.Observed");
  }

  @Test
  void rejectsPartialResultsWhenLaterInputsFail() throws IOException {
    final Path log = tempDir.resolve("classes.log");
    final Path missing = tempDir.resolve("missing.lst");
    final Path unsupported = tempDir.resolve("trace.bin");
    final Path malformed = tempDir.resolve("malformed.lst");
    Files.writeString(log, "[info][class,load] org.example.Valid source: file:/app.jar\n");
    Files.writeString(malformed, "not a class name\n");
    final CompositeTraceReader reader = new CompositeTraceReader();

    assertThatIOException().isThrownBy(() -> reader.readAll(List.of(log, missing)));
    assertThatIOException().isThrownBy(() -> reader.readAll(List.of(log, unsupported)));
    assertThatIOException().isThrownBy(() -> reader.readAll(List.of(log, malformed)));
  }

  @Test
  void rejectsNoSupportedTraceInputs() {
    final CompositeTraceReader reader = new CompositeTraceReader();

    assertThatIOException().isThrownBy(() -> reader.readAll(List.of()));
    assertThatIOException().isThrownBy(() -> reader.readAll(List.of(tempDir.resolve("trace.bin"))));
  }
}
