// WHY: Proves that source applicability comes from raw OSV and CVE version claims.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveSourceRecordMetadata;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.OsvAffectedPackage;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests the supported raw version semantics used for source matching and reports. */
final class MavenRawScopeApplicabilityTest {
  /** Affected status used by source claims. */
  private static final String AFFECTED = "affected";

  /** Unaffected status used by source claims. */
  private static final String UNAFFECTED = "unaffected";

  /** OSV range introduction key. */
  private static final String INTRODUCED = "introduced";

  /** OSV range exclusive boundary key. */
  private static final String FIXED = "fixed";

  /** First fixture version. */
  private static final String VERSION_1 = "1.0";

  /** Second fixture version. */
  private static final String VERSION_2 = "2.0";

  /** Third fixture version. */
  private static final String VERSION_3 = "3.0";

  /** Candidate between the second and third versions. */
  private static final String VERSION_2_5 = "2.5";

  /** Candidate outside the declared ranges. */
  private static final String VERSION_4 = "4.0";

  /** Maven version type claim. */
  private static final String MAVEN = "maven";

  /** CNA version-change status key. */
  private static final String STATUS = "status";

  /** OSV Maven ecosystem range type. */
  private static final String ECOSYSTEM = "ECOSYSTEM";

  /** Creates the focused evaluator test fixture. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  /* package */ MavenRawScopeApplicabilityTest() {}

  @Test
  void osvVersionsAreAnAlternativeToRangesAndZeroIsAnOpenSentinel() {
    final OsvAffectedPackage mixed =
        packageWith(
            List.of(VERSION_1),
            List.of(
                range(
                    ECOSYSTEM, List.of(Map.of(INTRODUCED, VERSION_2), Map.of(FIXED, VERSION_3)))));
    final OsvAffectedPackage fromZero =
        packageWith(
            List.of(),
            List.of(range(ECOSYSTEM, List.of(Map.of(INTRODUCED, "0"), Map.of(FIXED, VERSION_2)))));

    assertAll(
        "OSV listed versions and supported ranges form an affected-version union",
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(mixed, VERSION_1).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(mixed, VERSION_2_5).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(mixed, VERSION_4).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(fromZero, "1.9").status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(fromZero, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED));
  }

  @Test
  void unsupportedAndMalformedOsvRangesRemainUnknown() {
    final OsvAffectedPackage git =
        packageWith(
            List.of(),
            List.of(
                range("GIT", List.of(Map.of(INTRODUCED, VERSION_1), Map.of(FIXED, VERSION_3)))));
    final OsvAffectedPackage malformed =
        packageWith(List.of(), List.of(range(ECOSYSTEM, List.of(Map.of(FIXED, VERSION_3)))));

    assertAll(
        "unrecognized OSV range semantics cannot establish applicability",
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(git, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateOsv(malformed, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN));
  }

  @Test
  void missingDefaultUnknownStatusAndMatchedExactClaimsStayDistinct() {
    final CveAffectedEntryContext noDefault = entry(null, List.of());
    final CveAffectedEntryContext unknownDefault = entry("unknown", List.of());
    final CveAffectedEntryContext affectedDefault = entry(AFFECTED, List.of());
    final CveAffectedEntryContext unaffectedDefault = entry(UNAFFECTED, List.of());
    final CveAffectedEntryContext exactAffected =
        entry(null, List.of(claim(VERSION_1, AFFECTED, null, null, null, List.of())));
    final CveAffectedEntryContext customExact =
        entry(null, List.of(claim(VERSION_1, AFFECTED, "semver", null, null, List.of())));

    assertAll(
        "only a matching supported claim or recognized default determines status",
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(noDefault, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(unknownDefault, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(affectedDefault, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(
                    MavenRawScopeApplicability.evaluateCna(unaffectedDefault, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(exactAffected, VERSION_1).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(customExact, VERSION_1).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN));
  }

  @Test
  void cnaRangeBoundsAreExclusiveOrInclusiveAsDeclared() {
    final CveAffectedEntryContext exclusive =
        entry(null, List.of(claim(VERSION_1, AFFECTED, MAVEN, VERSION_2, null, List.of())));
    final CveAffectedEntryContext inclusive =
        entry(null, List.of(claim(VERSION_1, AFFECTED, MAVEN, null, VERSION_2, List.of())));

    assertAll(
        "CNA upper-bound spelling controls equality at the boundary",
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(exclusive, "1.9").status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(exclusive, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(inclusive, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED));
  }

  @Test
  void cnaChangesSortByMavenVersionAndRejectDuplicatesOrOverlappingClaims() {
    final CveAffectedEntryContext changes =
        entry(
            null,
            List.of(
                claim(
                    VERSION_1,
                    AFFECTED,
                    MAVEN,
                    VERSION_4,
                    null,
                    List.of(
                        Map.of("at", VERSION_2, STATUS, UNAFFECTED),
                        Map.of("at", VERSION_3, STATUS, AFFECTED)))));
    final CveAffectedEntryContext overlap =
        entry(
            null,
            List.of(
                claim(VERSION_1, AFFECTED, MAVEN, VERSION_3, null, List.of()),
                claim(VERSION_2, UNAFFECTED, MAVEN, VERSION_4, null, List.of())));
    final CveAffectedEntryContext shuffledChanges =
        entry(
            null,
            List.of(
                claim(
                    VERSION_1,
                    AFFECTED,
                    MAVEN,
                    VERSION_4,
                    null,
                    List.of(
                        Map.of("at", VERSION_3, STATUS, AFFECTED),
                        Map.of("at", VERSION_2, STATUS, UNAFFECTED)))));
    final CveAffectedEntryContext missingRangeType =
        entry(null, List.of(claim(VERSION_1, AFFECTED, null, VERSION_4, null, List.of())));
    final CveAffectedEntryContext duplicateChanges =
        entry(
            null,
            List.of(
                claim(
                    VERSION_1,
                    AFFECTED,
                    MAVEN,
                    VERSION_4,
                    null,
                    List.of(
                        Map.of("at", VERSION_2, STATUS, UNAFFECTED),
                        Map.of("at", "2", STATUS, AFFECTED)))));
    final CveAffectedEntryContext invalidChangeStatus =
        entry(
            null,
            List.of(
                claim(
                    VERSION_1,
                    AFFECTED,
                    MAVEN,
                    VERSION_4,
                    null,
                    List.of(Map.of("at", VERSION_2, STATUS, "not-a-cve-status")))));

    assertAll(
        "CNA changes sort by Maven versions and malformed claims abstain",
        () ->
            assertAll(
                "ordered change list transitions",
                () ->
                    assertThat(MavenRawScopeApplicability.evaluateCna(changes, "1.5").status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
                () ->
                    assertThat(MavenRawScopeApplicability.evaluateCna(changes, VERSION_2).status())
                        .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(changes, VERSION_2_5).status())
                        .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
                () ->
                    assertThat(MavenRawScopeApplicability.evaluateCna(changes, VERSION_3).status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
                () ->
                    assertThat(MavenRawScopeApplicability.evaluateCna(changes, "3.5").status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED)),
        () ->
            assertAll(
                "shuffled change list has identical transitions",
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(shuffledChanges, "1.5").status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(shuffledChanges, VERSION_2)
                                .status())
                        .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(shuffledChanges, VERSION_2_5)
                                .status())
                        .isEqualTo(MavenRawScopeApplicability.Status.UNAFFECTED),
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(shuffledChanges, VERSION_3)
                                .status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
                () ->
                    assertThat(
                            MavenRawScopeApplicability.evaluateCna(shuffledChanges, "3.5").status())
                        .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED)),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(overlap, VERSION_2_5).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(MavenRawScopeApplicability.evaluateCna(duplicateChanges, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(
                    MavenRawScopeApplicability.evaluateCna(invalidChangeStatus, VERSION_2).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN),
        () ->
            assertThat(
                    MavenRawScopeApplicability.evaluateCna(missingRangeType, VERSION_2_5).status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN));
  }

  @Test
  void structuredApplicabilityRequiresBothRawOwnersToAgree() {
    final OsvAffectedPackage osv = packageWith(List.of(VERSION_1), List.of());
    final CveAffectedEntryContext affected =
        entry(null, List.of(claim(VERSION_1, AFFECTED, null, null, null, List.of())));
    final CveAffectedEntryContext conflicting =
        entry(null, List.of(claim(VERSION_1, UNAFFECTED, null, null, null, List.of())));

    assertAll(
        "a positive decision requires both raw source owners",
        () ->
            assertThat(
                    MavenRawScopeApplicability.evaluateStructured(osv, affected, VERSION_1)
                        .status())
                .isEqualTo(MavenRawScopeApplicability.Status.AFFECTED),
        () ->
            assertThat(
                    MavenRawScopeApplicability.evaluateStructured(osv, conflicting, VERSION_1)
                        .status())
                .isEqualTo(MavenRawScopeApplicability.Status.UNKNOWN));
  }

  private static OsvAffectedPackage packageWith(
      final List<String> versions, final List<OsvAffectedRange> ranges) {
    return new OsvAffectedPackage(
        "Maven",
        "org.example:library",
        ArtifactCoordinate.of("org.example", "library", null),
        versions,
        ranges);
  }

  private static OsvAffectedRange range(final String type, final List<Map<String, String>> events) {
    return new OsvAffectedRange(type, null, events);
  }

  private static CveVersionClaim claim(
      final String version,
      final String status,
      final String versionType,
      final String lessThan,
      final String lessThanOrEqual,
      final List<Map<String, String>> changes) {
    return new CveVersionClaim(version, status, versionType, lessThan, lessThanOrEqual, changes);
  }

  private static CveAffectedEntryContext entry(
      final String defaultStatus, final List<CveVersionClaim> versions) {
    return new CveAffectedEntryContext(
        "containers.cna.affected[0]",
        new CveSourceRecordMetadata(
            true, true, true, "CVE-2026-12345", true, "PUBLISHED", "a".repeat(64)),
        "Example",
        "library",
        "pkg:maven/org.example/library",
        null,
        null,
        defaultStatus,
        versions,
        Set.of(),
        Set.of());
  }
}
