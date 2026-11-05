// WHY: Keeps upper-tier-retained classes out of prediction removal rows.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests upper-tier removal reporting. JUnit supplies the implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzePredictionTest {
  @Test
  void rejectsMultiplePlansForSameComponentAcrossScopes() {
    final io.github.spockz.elider.model.ArtifactCoordinate compile =
        io.github.spockz.elider.model.ArtifactCoordinate.of("org.example", "lib", "1");
    final io.github.spockz.elider.model.ArtifactCoordinate runtime =
        new io.github.spockz.elider.model.ArtifactCoordinate(
            "org.example", "lib", "1", "jar", "", "runtime");
    org.assertj.core.api.Assertions.assertThatThrownBy(
            () ->
                new AnalyzePrediction(
                    MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
                    java.util.List.of(),
                    java.util.List.of(compile),
                    java.util.List.of(),
                    java.util.List.of(
                        new AnalyzePrediction.PlannedTrim(compile, Set.of("p.One")),
                        new AnalyzePrediction.PlannedTrim(runtime, Set.of("p.Two"))),
                    new ElisionAnalysisModel.AnalysisEvidence(
                        new io.github.spockz.elider.engine.ClassUsageReport(java.util.List.of()),
                        java.util.Optional.empty(),
                        java.util.Map.of(),
                        false,
                        false,
                        null),
                    "a".repeat(64),
                    "b".repeat(64),
                    "c".repeat(64)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("multiple plans");
  }

  @Test
  void upperTierOnlyClassIsNotReportedAsPlannedRemoval() {
    final Set<String> removed =
        AnalyzePrediction.removedClasses(
            Set.of("api.Shared", "impl.OnlyInUpperTier", "impl.Removed"),
            Set.of("api/Shared"),
            Set.of("impl/OnlyInUpperTier"));

    assertThat(removed).containsOnly("impl.Removed");
  }
}
