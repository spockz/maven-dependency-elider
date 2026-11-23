// WHY: Proves saved test-view observations replay exactly and reject ambiguous or stale shapes.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies strict deterministic persistence of the separate test observation. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class TestViewReportWriterTest {
  /** Saved files share an isolated directory for each test. */
  @TempDir private Path directory;

  @Test
  void writesDeterministicPreparedReportAndReplaysSavedObservations() throws IOException {
    final Path production = directory.resolve("production.json");
    Files.writeString(production, "saved production result");
    final Path first = directory.resolve("first.json");
    final Path second = directory.resolve("second.json");
    final TestViewReportSnapshot snapshot = prepared(production);

    TestViewReportWriter.write(first, snapshot);
    TestViewReportWriter.write(second, snapshot);
    final TestViewReportSnapshot replayed = TestViewReportWriter.read(first);

    assertAll(
        "saved test view",
        () -> assertThat(Files.readAllBytes(first)).isEqualTo(Files.readAllBytes(second)),
        () -> assertThat(replayed).isEqualTo(snapshot),
        () ->
            assertThat(replayed.productionReportSha256())
                .isEqualTo(TestViewReportWriter.sha256(production)),
        () ->
            assertThat(replayed.inputArtifacts())
                .extracting(TestViewReportSnapshot.InputArtifact::identity)
                .containsExactly("a:compile", "z:test"),
        () ->
            assertThat(replayed.additions().getFirst().classes())
                .containsExactly("a/Builder", "a/Helper"),
        () ->
            assertThat(TestViewReportRenderer.render(replayed))
                .contains(
                    "Test view: prepared",
                    "Test-only added classes: 2 in 1 artifacts",
                    "Conservative test-only fallback: false"));
  }

  @Test
  void preservesValidPackageMetadataAndUnicodeClassNames() throws IOException {
    final Path saved = directory.resolve("package-metadata.json");
    final TestViewReportSnapshot snapshot =
        prepared(directory.resolve("production.json"), List.of("a/package-info", "a/Café"));

    TestViewReportWriter.write(saved, snapshot);

    assertAll(
        "class entries accepted by the addition archive also replay in the saved report",
        () -> assertThat(TestViewReportWriter.read(saved)).isEqualTo(snapshot),
        () ->
            assertThat(TestViewReportWriter.read(saved).additions().getFirst().classes())
                .containsExactly("a/Café", "a/package-info"));
  }

  @Test
  void unavailableReportHasAnExplicitReasonWithoutClaimingPreparedInputs() throws IOException {
    final TestViewReportSnapshot unavailable =
        new TestViewReportSnapshot(
            1,
            "org.example",
            "app",
            "1",
            directory.toRealPath().toString(),
            "a".repeat(64),
            TestViewReportSnapshot.Status.UNAVAILABLE,
            "Test compilation was skipped",
            null,
            List.of(),
            List.of(),
            null,
            false);
    final Path saved = directory.resolve("unavailable.json");

    TestViewReportWriter.write(saved, unavailable);

    assertAll(
        "unavailable test view",
        () -> assertThat(TestViewReportWriter.read(saved)).isEqualTo(unavailable),
        () ->
            assertThat(TestViewReportRenderer.render(unavailable))
                .contains("Test view: unavailable: Test compilation was skipped"),
        () ->
            assertThatThrownBy(
                    () ->
                        new TestViewReportSnapshot(
                            1,
                            "org.example",
                            "app",
                            "1",
                            directory.toString(),
                            "a".repeat(64),
                            TestViewReportSnapshot.Status.UNAVAILABLE,
                            "skipped",
                            "target/test-classes",
                            List.of(),
                            List.of(),
                            null,
                            false))
                .isInstanceOf(IllegalArgumentException.class));
  }

  @Test
  void rejectsMalformedVersionShapeAndJsonFraming() throws IOException {
    final Path valid = directory.resolve("valid.json");
    TestViewReportWriter.write(valid, prepared(directory.resolve("production.json")));
    final String body = Files.readString(valid);
    final List<String> invalid =
        List.of(
            body.replace("\"schemaVersion\" : 1", "\"schemaVersion\" : 2"),
            body.replace("\"schemaVersion\" : 1", "\"schemaVersion\" : 4294967297"),
            body.replace("\"schemaVersion\" : 1", "\"schemaVersion\" : null"),
            body.replace("\"status\" : \"PREPARED\"", "\"status\" : \"BOGUS\""),
            body.replace(
                "\"conservativeFallbackUsed\" : false", "\"conservativeFallbackUsed\" : \"false\""),
            body.replaceFirst("\\{", "{\"unknown\": true,"),
            body.replaceFirst("\\{", "{\"schemaVersion\":1,"),
            body + " {}");
    for (int index = 0; index < invalid.size(); index++) {
      final Path file = directory.resolve("invalid-" + index + ".json");
      Files.writeString(file, invalid.get(index));
      assertThatThrownBy(() -> TestViewReportWriter.read(file))
          .as("invalid report variant %s", index)
          .isInstanceOf(IOException.class);
    }
  }

  private TestViewReportSnapshot prepared(final Path production) throws IOException {
    return prepared(production, List.of("a/Helper", "a/Builder"));
  }

  private TestViewReportSnapshot prepared(final Path production, final List<String> classes)
      throws IOException {
    return new TestViewReportSnapshot(
        1,
        "org.example",
        "app",
        "1",
        directory.toRealPath().toString(),
        Files.exists(production) ? TestViewReportWriter.sha256(production) : "a".repeat(64),
        TestViewReportSnapshot.Status.PREPARED,
        null,
        directory.resolve("target/test-classes").toString(),
        List.of(
            new TestViewReportSnapshot.InputArtifact("z:test", "original-z.jar", null),
            new TestViewReportSnapshot.InputArtifact(
                "a:compile", "original-a.jar", "trimmed-a.jar")),
        List.of(new TestViewReportSnapshot.Addition("a:compile", classes)),
        directory.resolve("target/elider/test-additions.jar").toString(),
        false);
  }
}
