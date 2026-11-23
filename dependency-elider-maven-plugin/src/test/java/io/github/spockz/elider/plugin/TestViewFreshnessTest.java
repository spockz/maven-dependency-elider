/* WHY: Proves automatic test additions are reused only with identical clean-build inputs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises persisted test-view freshness across invocations. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier"
})
final class TestViewFreshnessTest {
  private static final String TEST_CLASS = "Test.class";
  private static final String RELEASE_OPTION = "release";
  private static final String CLEAN_WORD = "clean";
  @TempDir private Path directory;

  @Test
  void cleanPreparationRecordsDeterministicManifestAndMatchingReuseSucceeds() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    final byte[] first = Files.readAllBytes(fixture.manifest());
    fixture.check(false);
    fixture.check(true);
    assertAll(
        () -> assertThat(Files.readAllBytes(fixture.manifest())).isEqualTo(first),
        () ->
            assertThat(new String(first, java.nio.charset.StandardCharsets.UTF_8))
                .contains(
                    "\"schemaVersion\":1",
                    "\"formatId\":\"elider-test-view-freshness\"",
                    "\"categories\":{\"sources\":",
                    "\"test-output\":",
                    "\"main-output\":",
                    "\"artifacts\":",
                    "\"options-runtime\":")
                .doesNotContain(RELEASE_OPTION));
  }

  @Test
  void changedOrRemovedSourceRequiresCleanBuild() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    Files.writeString(fixture.source(), "edited");
    assertStale(fixture, "sources");
    Files.writeString(fixture.source(), "original");
    Files.delete(fixture.source());
    assertStale(fixture, "sources");
  }

  @Test
  void changedCompiledTestOrMainOutputRequiresCleanBuild() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    Files.writeString(fixture.testOutput().resolve(TEST_CLASS), "edited");
    assertStale(fixture, "test-output");
    Files.writeString(fixture.testOutput().resolve(TEST_CLASS), "test bytecode");
    Files.writeString(fixture.mainOutput().resolve("Main.class"), "edited");
    assertStale(fixture, "main-output");
    Files.writeString(fixture.mainOutput().resolve("Main.class"), "main bytecode");
    Files.delete(fixture.testOutput().resolve(TEST_CLASS));
    assertStale(fixture, "test-output");
  }

  @Test
  void changedOriginalOrEffectiveJarRequiresCleanBuild() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    Files.writeString(fixture.original(), "edited original");
    assertStale(fixture, "artifacts");
    Files.writeString(fixture.original(), "original jar");
    Files.writeString(fixture.effective(), "edited effective");
    assertStale(fixture, "artifacts");
  }

  @Test
  void changedConfigurationOrOrderedArtifactIdentityRequiresCleanBuild() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    assertThatThrownBy(
            () ->
                fixture.check(
                    false, Map.of(RELEASE_OPTION, "secret-option-value"), fixture.artifacts()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("options-runtime")
        .hasMessageContaining(CLEAN_WORD)
        .satisfies(
            failure -> assertThat(failure.getMessage()).doesNotContain("secret-option-value"));
    final List<TestAdditionsAnalyzer.ArtifactInput> renamed =
        List.of(
            new TestAdditionsAnalyzer.ArtifactInput(
                "renamed", fixture.original(), Optional.of(fixture.effective())));
    assertThatThrownBy(() -> fixture.check(false, Map.of(RELEASE_OPTION, "17"), renamed))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("artifacts")
        .hasMessageContaining(CLEAN_WORD);
  }

  @Test
  void changedEliderEmbeddedSbomsInvalidateMainOutput() throws Exception {
    final Fixture fixture = fixture();
    fixture.check(true);
    final Path nativeSbom = fixture.mainOutput().resolve("META-INF/native-image/sbom.json");
    final Path applicationSbom = fixture.mainOutput().resolve("META-INF/sbom/application.cdx.json");
    Files.createDirectories(nativeSbom.getParent());
    Files.createDirectories(applicationSbom.getParent());
    Files.writeString(nativeSbom, "first generated document");
    Files.writeString(applicationSbom, "first generated document");
    assertStale(fixture, "main-output");
    fixture.check(true);
    Files.writeString(nativeSbom, "second generated document");
    Files.writeString(applicationSbom, "second generated document");
    assertStale(fixture, "main-output");
  }

  @Test
  void absentOrMalformedManifestFailsClosed() throws Exception {
    final Fixture fixture = fixture();
    assertStale(fixture);
    fixture.check(true);
    final String valid = Files.readString(fixture.manifest());
    for (final String malformed :
        List.of(
            "not json",
            valid.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            valid.replace("\"schemaVersion\":1,", "\"schemaVersion\":1,\"schemaVersion\":1,"),
            valid.replace("\"main-output\":", "\"unexpected-output\":"),
            valid.replace("\"test-output\":\"", "\"test-output\":\"bad"),
            valid.replaceFirst(
                "\"fingerprint\":\"[0-9a-f]{64}\"", "\"fingerprint\":\"" + "0".repeat(64) + "\""),
            valid.substring(0, valid.length() - 1) + ",\"extra\":true}",
            valid + " true")) {
      Files.writeString(fixture.manifest(), malformed);
      assertStale(fixture);
    }
  }

  private void assertStale(final Fixture fixture) {
    assertThatThrownBy(() -> fixture.check(false))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(CLEAN_WORD);
  }

  private void assertStale(final Fixture fixture, final String category) {
    assertThatThrownBy(() -> fixture.check(false))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(category)
        .hasMessageContaining(CLEAN_WORD);
  }

  private Fixture fixture() throws IOException {
    final Path sourceRoot = Files.createDirectory(directory.resolve("src"));
    final Path source = sourceRoot.resolve("Test.java");
    Files.writeString(source, "original");
    final Path testOutput = Files.createDirectory(directory.resolve("test-classes"));
    Files.writeString(testOutput.resolve(TEST_CLASS), "test bytecode");
    final Path mainOutput = Files.createDirectory(directory.resolve("classes"));
    Files.writeString(mainOutput.resolve("Main.class"), "main bytecode");
    final Path original = directory.resolve("original.jar");
    final Path effective = directory.resolve("effective.jar");
    Files.writeString(original, "original jar");
    Files.writeString(effective, "effective jar");
    return new Fixture(
        directory.resolve("freshness.json"),
        sourceRoot,
        source,
        testOutput,
        mainOutput,
        original,
        effective);
  }

  private record Fixture(
      Path manifest,
      Path sourceRoot,
      Path source,
      Path testOutput,
      Path mainOutput,
      Path original,
      Path effective) {
    List<TestAdditionsAnalyzer.ArtifactInput> artifacts() {
      return List.of(
          new TestAdditionsAnalyzer.ArtifactInput("library", original, Optional.of(effective)));
    }

    void check(final boolean cleaned) throws IOException {
      check(cleaned, Map.of(RELEASE_OPTION, "17"), artifacts());
    }

    void check(
        final boolean cleaned,
        final Map<String, String> options,
        final List<TestAdditionsAnalyzer.ArtifactInput> inputs)
        throws IOException {
      TestViewFreshness.verifyOrRecord(
          manifest, cleaned, testOutput, mainOutput, List.of(sourceRoot), inputs, options);
    }
  }
}
