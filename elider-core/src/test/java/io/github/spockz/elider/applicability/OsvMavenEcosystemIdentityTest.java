// WHY: Ensures only supported Maven ecosystem identities authorize raw OSV version claims.

package io.github.spockz.elider.applicability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAffectedPackage;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Checks the exact Maven ecosystem gate before explicit-version evaluation. */
final class OsvMavenEcosystemIdentityTest {
  /** Explicit candidate version in the source claims. */
  private static final String VERSION = "1.0";

  /** Creates the test instance explicitly for PMD constructor policy. */
  /* package */ OsvMavenEcosystemIdentityTest() {
    // No fixture state is needed.
  }

  @Test
  void exactMavenEcosystemIsCheckedBeforeExplicitVersionClaims() {
    final OsvAffectedPackage prefixCollision = packageWith("Mavenish");
    final OsvAffectedPackage customMaven = packageWith("maven:custom");

    assertAll(
        "explicit versions cannot bypass the exact ecosystem identity gate",
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(prefixCollision, VERSION).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(customMaven, VERSION).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED));
  }

  private static OsvAffectedPackage packageWith(final String ecosystem) {
    return new OsvAffectedPackage(
        ecosystem,
        "org.example:library",
        ArtifactCoordinate.of("org.example", "library", null),
        List.of(VERSION),
        List.of());
  }
}
