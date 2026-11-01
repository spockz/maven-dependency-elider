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
  /** Canonical Maven ecosystem label used by the fixtures. */
  private static final String MAVEN_ECOSYSTEM = "Maven";

  /** Exact group and artifact used by the fixtures. */
  private static final String PACKAGE_NAME = "org.example:library";

  /** Supported ecosystem range type. */
  private static final String ECOSYSTEM_RANGE = "ECOSYSTEM";

  /** First fixture lower bound. */
  private static final String VERSION_1 = "1.0";

  /** Second fixture upper bound. */
  private static final String VERSION_3 = "3.0";

  /** Upper endpoint of the second disjoint fixture range. */
  private static final String VERSION_4 = "4.0";

  /** Concrete affected version used by the exact-version fixture. */
  private static final String VERSION_EXACT = "1.2";

  /** Concrete version absent from the exact-version fixture. */
  private static final String VERSION_UNLISTED = "1.3";

  /** Concrete version inside the first interval. */
  private static final String VERSION_1_9 = "1.9";

  /** Concrete version inside and at the boundary of fixture ranges. */
  private static final String VERSION_2_5 = "2.5";

  /** Concrete version inside the second disjoint interval. */
  private static final String VERSION_3_5 = "3.5";

  /** Concrete version inside the unsupported-range fixture. */
  private static final String VERSION_1_5 = "1.5";

  /** Unsupported source range type. */
  private static final String GIT_RANGE = "GIT";

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
  void reportsExactVersionsAndSupportedMavenRangesAsAnAffectedUnion() {
    final OsvAffectedPackage exact =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM, PACKAGE_NAME, PACKAGE, List.of(VERSION_EXACT), List.of());
    final OsvAffectedPackage interval =
        packageWithRange(
            ECOSYSTEM_RANGE, List.of(Map.of(INTRODUCED, VERSION_1), Map.of(FIXED, VERSION_2)));

    assertAll(
        "only preserved exact versions and one Maven interval can assert applicability",
        () ->
            assertThat(OsvPackageApplicability.evaluate(exact, VERSION_EXACT).status())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(exact, VERSION_UNLISTED).status())
                .isEqualTo(OsvPackageApplicability.Status.NOT_APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(interval, VERSION_1_9).status())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(interval, VERSION_2).status())
                .isEqualTo(OsvPackageApplicability.Status.NOT_APPLICABLE));
  }

  @Test
  void unionsSupportedRangesAndRefusesUnsupportedOrOverlappingEvents() {
    final OsvAffectedPackage git =
        packageWithRange(
            GIT_RANGE, List.of(Map.of(INTRODUCED, VERSION_1), Map.of(FIXED, VERSION_2)));
    final OsvAffectedPackage multipleRanges =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM,
            PACKAGE_NAME,
            PACKAGE,
            List.of(),
            List.of(
                new OsvAffectedRange(
                    ECOSYSTEM_RANGE,
                    null,
                    List.of(Map.of(INTRODUCED, VERSION_1), Map.of(FIXED, VERSION_2))),
                new OsvAffectedRange(
                    ECOSYSTEM_RANGE,
                    null,
                    List.of(Map.of(INTRODUCED, VERSION_3), Map.of(FIXED, VERSION_4)))));
    final OsvAffectedPackage overlappingEvents =
        packageWithRange(
            ECOSYSTEM_RANGE,
            List.of(
                Map.of(INTRODUCED, VERSION_1),
                Map.of(FIXED, VERSION_3),
                Map.of(INTRODUCED, VERSION_2),
                Map.of(FIXED, VERSION_4)));
    final OsvAffectedPackage supportedWithUnsupportedSibling =
        new OsvAffectedPackage(
            MAVEN_ECOSYSTEM,
            PACKAGE_NAME,
            PACKAGE,
            List.of(),
            List.of(
                new OsvAffectedRange(
                    ECOSYSTEM_RANGE,
                    null,
                    List.of(Map.of(INTRODUCED, VERSION_3), Map.of(FIXED, VERSION_4))),
                new OsvAffectedRange(
                    GIT_RANGE,
                    null,
                    List.of(Map.of(INTRODUCED, VERSION_1), Map.of(FIXED, VERSION_2)))));

    assertAll(
        "supported OSV ranges form a union while malformed or unsupported claims stay unknown",
        () ->
            assertThat(OsvPackageApplicability.evaluate(git, VERSION_1_5).status())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED),
        () ->
            assertThat(OsvPackageApplicability.evaluate(multipleRanges, VERSION_3_5).status())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(OsvPackageApplicability.evaluate(overlappingEvents, VERSION_2_5).status())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED),
        () ->
            assertThat(
                    OsvPackageApplicability.evaluate(supportedWithUnsupportedSibling, VERSION_3_5)
                        .status())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED));
  }

  private static OsvAffectedPackage packageWithRange(
      final String type, final List<Map<String, String>> events) {
    return new OsvAffectedPackage(
        MAVEN_ECOSYSTEM,
        PACKAGE_NAME,
        PACKAGE,
        List.of(),
        List.of(new OsvAffectedRange(type, null, events)));
  }
}
