// WHY: Exercises digest-bound refusal when raw source or archive bytes change during proof.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;
import org.eclipse.aether.RepositorySystemSession;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Confirms stale live inputs cannot produce structured omitted-code VEX. */
final class MavenStructuredProofMutationGuardTest {
  /** Trimmed archive name used by isolated cases. */
  private static final String TRIMMED_JAR = "trimmed.jar";

  /** Test filesystem root. */
  @TempDir private Path temporaryDirectory;

  /** Creates an isolated mutation-guard test instance. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  MavenStructuredProofMutationGuardTest() {}

  @ParameterizedTest
  @EnumSource(InputMutation.class)
  void staleCurrentInputsAndChangedArchivesAbstain(final InputMutation mutation)
      throws IOException {
    final Path directory = temporaryDirectory.resolve(mutation.name());
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            directory, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(directory, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(directory.resolve(TRIMMED_JAR));
    final Consumer<RepositorySystemSession> mutationAtResolve =
        ignored -> {
          try {
            mutation.apply(prepared, archives, trimmed);
          } catch (final IOException exception) {
            throw new UncheckedIOException(exception);
          }
        };

    final MavenCorroboratedSourceScenario.AssessmentWithLog assessment =
        MavenStructuredProofScenario.assessWithDebugLog(
            prepared, archives, trimmed, true, mutationAtResolve);
    final MavenVulnerabilityAssessment.Result result = assessment.result();

    assertAll(
        mutation + " mutation is rejected by its live digest guard",
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty(),
        () ->
            assertThat(assessment.log().debugMessages())
                .anyMatch(message -> message.contains(mutation.diagnostic())));
  }

  /** Mutations applied after Maven selects a proof candidate. */
  private enum InputMutation {
    CNA_SOURCE_RECORD("Current CVE source bytes no longer authorize") {
      @Override
      /* default */ void apply(
          final MavenCorroboratedSourceScenario.Prepared prepared,
          final MavenSourceCorrespondenceTestArtifacts.Archives archives,
          final Path trimmed)
          throws IOException {
        MavenStructuredProofCacheFixtures.mutateCurrentCveRecord(prepared);
      }
    },
    ORIGINAL_ARCHIVE("Source reproduction does not match the exact trim candidate") {
      @Override
      /* default */ void apply(
          final MavenCorroboratedSourceScenario.Prepared prepared,
          final MavenSourceCorrespondenceTestArtifacts.Archives archives,
          final Path trimmed)
          throws IOException {
        MavenAdversarialSourceArchiveFixtures.addResourceWhilePreservingJarEntries(
            archives.originalJar());
      }
    },
    TRIMMED_OUTPUT("Artifact digest no longer matches trim record") {
      @Override
      /* default */ void apply(
          final MavenCorroboratedSourceScenario.Prepared prepared,
          final MavenSourceCorrespondenceTestArtifacts.Archives archives,
          final Path trimmed)
          throws IOException {
        MavenAdversarialSourceArchiveFixtures.addResourceWhilePreservingJarEntries(trimmed);
      }
    };

    /** Diagnostic emitted by the specific live-input refusal. */
    private final String expectedReason;

    InputMutation(final String expectedReason) {
      this.expectedReason = expectedReason;
    }

    /* default */ String diagnostic() {
      return expectedReason;
    }

    /* default */ abstract void apply(
        MavenCorroboratedSourceScenario.Prepared prepared,
        MavenSourceCorrespondenceTestArtifacts.Archives archives,
        Path trimmed)
        throws IOException;
  }
}
