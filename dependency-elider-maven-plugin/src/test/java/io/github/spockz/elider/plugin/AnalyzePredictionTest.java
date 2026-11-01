// WHY: Prevents prediction rows from calling retained upper-tier classes planned removals.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

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
