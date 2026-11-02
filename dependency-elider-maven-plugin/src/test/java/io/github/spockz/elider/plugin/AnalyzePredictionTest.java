// WHY: Keeps upper-tier-retained classes out of prediction removal rows.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests upper-tier removal reporting. JUnit supplies the implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzePredictionTest {
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
