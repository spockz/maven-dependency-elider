// WHY: Proves report applicability never inherits a flattened unsupported OSV range.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Tests that report applicability preserves raw OSV uncertainty. */
final class OsvPackageApplicabilityTest {
  /** OSV introduced event key. */
  private static final String INTRODUCED = "introduced";

  /** OSV fixed event key. */
  private static final String FIXED = "fixed";

  /** Reused end version. */
  private static final String VERSION_2 = "2.0";

  /** Shared Maven package coordinate. */
  private static final ArtifactCoordinate PACKAGE =
      ArtifactCoordinate.of("org.example", "library", null);

  /** Creates the package applicability test fixture. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  OsvPackageApplicabilityTest() {}

  @Test
  void reportsExactVersionsAndOneSupportedMavenInterval() {
    final OsvAffectedPackage exact =
        new OsvAffectedPackage("Maven", "org.example:library", PACKAGE, List.of("1.2"), List.of());
    final OsvAffectedPackage interval =
        packageWithRange("ECOSYSTEM", List.of(Map.of(INTRODUCED, "1.0"), Map.of(FIXED, VERSION_2)));

    assertAll(
        "only preserved exact versions and one Maven interval can assert applicability",
        () ->
            assertThat(OsvPackageApplicability.evaluate(exact, "1.2").status())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(exact, "1.3").status())
                .isEqualTo(OsvPackageApplicability.Status.NOT_APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(interval, "1.9").status())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(interval, "2.0").status())
                .isEqualTo(OsvPackageApplicability.Status.NOT_APPLICABLE));
  }

  @Test
  void unsupportedGitAndNonContiguousRangesRemainUnresolved() {
    final OsvAffectedPackage git =
        packageWithRange("GIT", List.of(Map.of(INTRODUCED, "1.0"), Map.of(FIXED, VERSION_2)));
    final OsvAffectedPackage multiple =
        new OsvAffectedPackage(
            "Maven",
            "org.example:library",
            PACKAGE,
            List.of(),
            List.of(
                new OsvAffectedRange(
                    "ECOSYSTEM",
                    null,
                    List.of(Map.of(INTRODUCED, "1.0"), Map.of(FIXED, VERSION_2))),
                new OsvAffectedRange(
                    "ECOSYSTEM", null, List.of(Map.of(INTRODUCED, "3.0"), Map.of(FIXED, "4.0")))));

    assertAll(
        "unsupported range semantics are explicit report uncertainty",
        () ->
            assertThat(OsvPackageApplicability.evaluate(git, "1.5").status())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED),
        () ->
            assertThat(OsvPackageApplicability.evaluate(multiple, "1.5").status())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED));
  }

  private static OsvAffectedPackage packageWithRange(
      final String type, final List<Map<String, String>> events) {
    return new OsvAffectedPackage(
        "Maven",
        "org.example:library",
        PACKAGE,
        List.of(),
        List.of(new OsvAffectedRange(type, null, events)));
  }
}
