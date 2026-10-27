// WHY: Guards Maven version range boundaries and recommended-version interpretation.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

final class MavenVersionRangeMatcherTest {
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
}
