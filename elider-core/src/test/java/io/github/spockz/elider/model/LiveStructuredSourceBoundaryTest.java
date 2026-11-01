// WHY: Refuses live source requests that escape their checkout or omit an exact candidate version.

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks live source request identity and checkout containment. */
final class LiveStructuredSourceBoundaryTest {
  /** Per-test isolated source tree and cache location. */
  @TempDir private Path temporaryDirectory;

  /** Provides JUnit's package-visible constructor for per-scenario lifecycle. */
  /* default */ LiveStructuredSourceBoundaryTest() {
    // JUnit initializes the temporary directory after constructing each test instance.
  }

  @Test
  void rejectsCandidateWithoutConcreteVersion() throws Exception {
    final LiveStructuredSourceValidatorTest.Fixture fixture =
        LiveStructuredSourceValidatorTest.fixture(
            temporaryDirectory,
            LiveStructuredSourceValidatorTest.cveJson(
                LiveStructuredSourceValidatorTest.AFFECTED_STATUS, false));
    final StructuredSourceProofRequest request = fixture.request();
    final StructuredSourceProofRequest unversioned =
        new StructuredSourceProofRequest(
            request.osvId(),
            request.sourceEvidence(),
            ArtifactCoordinate.of(
                LiveStructuredSourceValidatorTest.GROUP_ID,
                LiveStructuredSourceValidatorTest.ARTIFACT_ID,
                null),
            request.cveListGitDir(),
            request.advisoryIndex(),
            request.expectedProducer(),
            request.sourcesJar(),
            request.sourcesCoordinate(),
            request.sourceRepositoryProvenance(),
            request.conventionalLayoutAssumed());

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(unversioned))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("exact owner candidate");
  }

  @Test
  void rejectsContradictoryVersionOnEvidenceScope() throws Exception {
    final LiveStructuredSourceValidatorTest.Fixture fixture =
        LiveStructuredSourceValidatorTest.fixture(
            temporaryDirectory,
            LiveStructuredSourceValidatorTest.cveJson(
                LiveStructuredSourceValidatorTest.AFFECTED_STATUS, false),
            "2.0",
            "Maven");

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(fixture.request()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("exact owner candidate");
  }

  @Test
  void rejectsUnsupportedEcosystemThatOnlySharesMavenPrefix() throws Exception {
    final LiveStructuredSourceValidatorTest.Fixture fixture =
        LiveStructuredSourceValidatorTest.fixture(
            temporaryDirectory,
            LiveStructuredSourceValidatorTest.cveJson(
                LiveStructuredSourceValidatorTest.AFFECTED_STATUS, false),
            null,
            "Mavenish");

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(fixture.request()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("unique exact Maven package claim");
  }

  @Test
  void rejectsCvesSymlinkThatEscapesConfiguredCheckout() throws Exception {
    final LiveStructuredSourceValidatorTest.Fixture fixture =
        LiveStructuredSourceValidatorTest.fixture(
            temporaryDirectory,
            LiveStructuredSourceValidatorTest.cveJson(
                LiveStructuredSourceValidatorTest.AFFECTED_STATUS, false));
    final Path checkout = fixture.request().cveListGitDir();
    final Path cvesRoot = checkout.resolve("cves");
    final Path outsideRoot = temporaryDirectory.resolve("outside-cves");
    final Path outsideRecord =
        outsideRoot
            .resolve("2025/12xxx")
            .resolve(LiveStructuredSourceValidatorTest.CVE_ID + ".json");
    Files.createDirectories(outsideRecord.getParent());
    Files.move(fixture.sourcePath(), outsideRecord);
    Files.delete(cvesRoot.resolve("2025/12xxx"));
    Files.delete(cvesRoot.resolve("2025"));
    Files.delete(cvesRoot);
    Files.createSymbolicLink(cvesRoot, outsideRoot);

    assertThatThrownBy(() -> LiveStructuredSourceValidator.observe(fixture.request()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("outside the CVE directory");
  }
}
