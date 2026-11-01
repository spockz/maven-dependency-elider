// WHY: Keeps independent unresolved source-claim scenarios from suppressing one another.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks file-only and routine-only structured claims independently. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenCorroboratedUnresolvedClaimAssessmentTest {
  /** Temporary root for source, cache, and archive fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void fileOnlyAndRoutineOnlyClaimsRemainBoundReviewRows() {
    assertAll(
        "unresolved source claims stay review data with optional matches",
        () -> assertFileOnly(temporaryDirectory.resolve("file-only")),
        () -> assertRoutineOnly(temporaryDirectory.resolve("routine-only")));
  }

  private static void assertFileOnly(final Path directory) throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepareUnresolvedClaim(directory, false);
    assertAll(
        () -> assertThat(scenario.result().matchedSourceClaims()).hasSize(1),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().coordinate())
                .isEqualTo(scenario.coordinate()),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().programFiles())
                .containsExactly("src/main/java/org/elsewhere/Outer.java"),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().programRoutines())
                .isEmpty(),
        () -> assertThat(scenario.result().matchedSourceClaims().getFirst().matches()).isEmpty(),
        () -> assertThat(scenario.result().attestations()).isEmpty(),
        () -> assertThat(scenario.result().removedComponents()).isEmpty());
  }

  private static void assertRoutineOnly(final Path directory) throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepareUnresolvedClaim(directory, true);
    assertAll(
        () -> assertThat(scenario.result().matchedSourceClaims()).hasSize(1),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().coordinate())
                .isEqualTo(scenario.coordinate()),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().programFiles()).isEmpty(),
        () ->
            assertThat(scenario.result().matchedSourceClaims().getFirst().programRoutines())
                .containsExactly("parse"),
        () -> assertThat(scenario.result().matchedSourceClaims().getFirst().matches()).isEmpty(),
        () -> assertThat(scenario.result().attestations()).isEmpty(),
        () -> assertThat(scenario.result().removedComponents()).isEmpty());
  }
}
