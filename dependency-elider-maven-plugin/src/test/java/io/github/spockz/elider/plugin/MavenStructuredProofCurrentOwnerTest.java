// WHY: Exercises current-index ambiguity introduced after Maven selected a structured claim.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import org.eclipse.aether.RepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Rechecks CVE owners after selecting a proof candidate. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenStructuredProofCurrentOwnerTest {
  /** Class family expected from the verified source entry. */
  private static final String OUTER = "org.example.Outer";

  /** Sibling class from the same source file. */
  private static final String SIBLING = "org.example.Sibling";

  /** Output path shared by isolated mutation scenarios. */
  private static final String TRIMMED_JAR = "trimmed.jar";

  /** Isolated assessment fixtures. */
  @TempDir private Path temporaryDirectory;

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void competingStructuredOwnerBlocksInEitherIndexOrder(final boolean reverse) throws IOException {
    assertMutationRefusal(
        "structured-owner-" + reverse,
        "Current index has competing CVE owner claims",
        (prepared, archives, trimmed) ->
            MavenStructuredProofOwnerCacheFixtures.addStructuredOwner(prepared, reverse));
  }

  @ParameterizedTest
  @CsvSource({"false,false", "false,true", "true,false", "true,true"})
  void packageOnlyOwnerBlocksForUnaffectedOrUnknownScope(
      final boolean unknownScope, final boolean reverse) throws IOException {
    assertMutationRefusal(
        "package-owner-" + unknownScope + "-" + reverse,
        "Current index has competing CVE owner claims",
        (prepared, archives, trimmed) ->
            MavenStructuredProofOwnerCacheFixtures.addPackageOnlyOwner(
                prepared, unknownScope, reverse));
  }

  @Test
  void unrelatedMavenProductForTheSameCveDoesNotBlockProof() throws IOException {
    final Scenario scenario = scenario("unrelated-product");
    final Consumer<RepositorySystemSession> mutation =
        ignored ->
            mutate(
                scenario,
                (prepared, archives, trimmed) ->
                    MavenStructuredProofOwnerCacheFixtures.addUnrelatedPackageOwner(prepared));
    final MavenVulnerabilityAssessment.Result result = assess(scenario, mutation).result();

    assertAll(
        "same-CVE records for another Maven package remain separate",
        () ->
            assertThat(result.attestations())
                .singleElement()
                .satisfies(
                    attestation ->
                        assertThat(attestation.evidenceSymbols()).contains(OUTER, SIBLING)),
        () -> assertThat(result.provenVulnerableCodeAbsent()).hasSize(1));
  }

  @Test
  void caseVariantMavenEcosystemStillBlocksTheSamePackage() throws IOException {
    assertMutationRefusal(
        "case-variant-package",
        "Current index has competing CVE owner claims",
        (prepared, archives, trimmed) ->
            MavenStructuredProofOwnerCacheFixtures.addCaseVariantPackageOwner(prepared));
  }

  private void assertMutationRefusal(
      final String scenarioName,
      final String expectedDiagnostic,
      final PreparedMutation preparedMutation)
      throws IOException {
    final Scenario scenario = scenario(scenarioName);
    final Consumer<RepositorySystemSession> mutation =
        ignored -> mutate(scenario, preparedMutation);
    final MavenCorroboratedSourceScenario.AssessmentWithLog assessment = assess(scenario, mutation);
    final MavenVulnerabilityAssessment.Result result = assessment.result();

    assertAll(
        scenarioName + " rejects current-index conflicts after source resolution",
        () -> assertThat(scenario.trimmedJar()).exists().isRegularFile(),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
        () ->
            assertThat(assessment.log().debugMessages())
                .anyMatch(message -> message.contains(expectedDiagnostic)));
  }

  private Scenario scenario(final String name) throws IOException {
    final Path directory = temporaryDirectory.resolve(name);
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(directory.resolve(TRIMMED_JAR));
    return new Scenario(prepared, archives, trimmed);
  }

  private static MavenCorroboratedSourceScenario.AssessmentWithLog assess(
      final Scenario scenario, final Consumer<RepositorySystemSession> mutation)
      throws IOException {
    return MavenStructuredProofScenario.assessWithDebugLog(
        scenario.prepared(), scenario.archives(), scenario.trimmedJar(), true, mutation);
  }

  private static void mutate(final Scenario scenario, final PreparedMutation mutation) {
    try {
      mutation.apply(scenario.prepared(), scenario.archives(), scenario.trimmedJar());
    } catch (final IOException exception) {
      throw new UncheckedIOException(exception);
    }
  }

  private record Scenario(
      MavenCorroboratedSourceScenario.Prepared prepared,
      MavenSourceCorrespondenceTestArtifacts.Archives archives,
      Path trimmedJar) {}

  /** Mutation receives the exact prepared inputs selected by Maven assessment. */
  @FunctionalInterface
  private interface PreparedMutation {
    /** Rewrites the fixture's cached advisory inputs. */
    void apply(
        MavenCorroboratedSourceScenario.Prepared prepared,
        MavenSourceCorrespondenceTestArtifacts.Archives archives,
        Path trimmedJar)
        throws IOException;
  }
}
