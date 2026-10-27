// WHY: Guards Maven version range boundaries and recommended-version interpretation.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** Verifies Maven version range boundaries and recommended-version behavior. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenVersionRangeMatcherTest {
  /** Creates the test fixture. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  MavenVersionRangeMatcherTest() {}

  @Test
  void evaluatesExplicitBoundsAndQualifierOrdering() {
    assertThat(MavenVersionRangeMatcher.includes("[1.5.0,1.6.0)", "1.5.0")).isTrue();
    assertThat(MavenVersionRangeMatcher.includes("[1.5.0,1.6.0)", "1.6.0")).isFalse();
    assertThat(MavenVersionRangeMatcher.includes("[1.5.0,1.5.1)", "1.5.0.Final")).isTrue();
    assertThat(MavenVersionRangeMatcher.includes("[1.5.0,1.5.1)", "1.5.0-beta-1")).isFalse();
  }

  @Test
  void treatsBareRecommendedVersionAsExact() {
    assertThat(MavenVersionRangeMatcher.includes("1.5.18", "1.5.18")).isTrue();
    assertThat(MavenVersionRangeMatcher.includes("1.5.18", "1.5.19")).isFalse();
  }

  @Test
  void malformedRangeFailsWhileValidNonmatchIsFalse() {
    assertThat(MavenVersionRangeMatcher.includes("[1.0,2.0)", "2.0")).isFalse();
    assertThatThrownBy(() -> MavenVersionRangeMatcher.includes("[1.0,2.0", "1.5"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid Maven version range")
        .hasMessageContaining("[1.0,2.0");
  }
}
