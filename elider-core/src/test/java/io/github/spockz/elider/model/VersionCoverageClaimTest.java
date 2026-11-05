/* WHY: Prevents unresolved coverage from being confused with negative applicability. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/** Verifies that coverage states retain their diagnostic meaning. */
class VersionCoverageClaimTest {
  /** Creates a test instance. */
  /* package */
  VersionCoverageClaimTest() {
    super();
  }

  @Test
  void unsupportedCoverageCannotHaveResolvedStatus() {
    assertThatThrownBy(
            () ->
                new VersionCoverageClaim(
                    "raw", null, VersionApplicability.AFFECTED, "unsupported predicate"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void boundedUnresolvedCoverageRequiresItsDiagnostic() {
    assertThatThrownBy(
            () ->
                new VersionCoverageClaim("raw", "[1.0,2.0)", VersionApplicability.UNRESOLVED, null))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
