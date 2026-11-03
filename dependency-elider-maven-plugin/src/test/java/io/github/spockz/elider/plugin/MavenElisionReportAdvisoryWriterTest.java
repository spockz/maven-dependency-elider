// WHY: Covers the historical report serialization and rendering of advisory-only rows.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.EvidenceOrigin;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests saved advisory rows separately from proof classifications. */
final class MavenElisionReportAdvisoryWriterTest {
  /** Shared synthetic artifact group. */
  private static final String GROUP_ID = "org.example";

  /** Artifact used for the removed package-advisory case. */
  private static final String REMOVED_ARTIFACT = "removed";

  /** Candidate class used by typed heuristic fixtures. */
  private static final String CANDIDATE_CLASS = "org.example.Candidate";

  /** Artifact used by heuristic owner fixtures. */
  private static final String TRIMMED_ARTIFACT = "trimmed";

  /** Stable version for fixture coordinates. */
  private static final String VERSION = "1.0";

  /** Second stable version used in heuristic scope fixtures. */
  private static final String SECOND_VERSION = "2.0";

  /** CVE alias shared by the heuristic owner fixtures. */
  private static final String CVE_ALIAS = "CVE-2026-12345";

  /** Canonical ecosystem string used by Maven package fixtures. */
  private static final String MAVEN_ECOSYSTEM = "Maven";

  /** Exact-version applicability rationale used by typed report fixtures. */
  private static final String EXACT_VERSION_RATIONALE =
      "Exact version is listed by the OSV affected package";

  /** Stable time in the persisted report fixture. */
  private static final String GENERATED_AT = "2026-10-26T16:00:00Z";

  /** Isolated report output directory. */
  @TempDir private Path temporaryDirectory;

  /** Creates this JUnit fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenElisionReportAdvisoryWriterTest() {}

  @Test
  void writesReadsAndRendersPackageAndHeuristicAdvisoryRowsSeparately() throws IOException {
    final MavenElisionReportSnapshot populated = snapshot().withAdvisoryReview(advisoryReview());
    final Path output = temporaryDirectory.resolve("advisory-review-report.json");

    MavenElisionReportWriter.write(output, populated);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);
    final List<String> rendered = MavenElisionReportWriter.render(reread);

    assertAll(
        "advisories remain historical review rows, separate from proof classifications",
        () -> assertThat(reread).isEqualTo(populated),
        () ->
            assertThat(rendered)
                .contains(
                    "Advisory associations (review only; inventory disposition is not impact"
                        + " proof):",
                    "    Heuristic candidates are review leads; they do not establish a complete",
                    "    affected class set.",
                    "    Add a POM mapping with HIGH only after verifying the source applies to"
                        + " the",
                    "    exact artifact version and the listed classes form the complete"
                        + " affected",
                    "    set.",
                    "    The elider still checks the original and trimmed artifacts before"
                        + " publishing",
                    "    VEX. Keep unverified candidates review-only.",
                    "    REMOVED means excluded from this project's subsequent classpaths; the"
                        + " cached",
                    "    JAR is not deleted.",
                    "  - GHSA-package-only org.example:removed:jar:1.0 (compile) [REMOVED]",
                    "    Aliases: none",
                    "    Affected-version applicability: UNRESOLVED"
                        + " (GIT ranges are not evaluated by this report)",
                    "    OSV ranges: GIT range for https://example.test/repo: aField = a, zField = z",
                    "  - GHSA-heuristic / CVE-2026-12345 org.example:trimmed:jar:2.0 (compile)"
                        + " [RETAINED_AND_TRIMMED]",
                    "    Heuristic origin: REFERENCE_URL / GHSA-heuristic#reference:0"
                        + " (MEDIUM)",
                    "    Affected-version applicability: APPLICABLE"
                        + " (Exact OSV version claim applies)",
                    "    Heuristic candidate scope: [2.0,3.0)"
                        + " (not used as raw OSV applicability)",
                    "    Source URL: https://example.test/commit/abc123?diff=split&w=1",
                    "    POM mapping template for this candidate:",
                    "      <vulnerabilityMappings>",
                    "        <vulnerabilityMapping>",
                    "          <cveId>CVE-2026-12345</cveId>",
                    "          <groupId>org.example</groupId>",
                    "          <artifactId>trimmed</artifactId>",
                    "          <versionRangeSpec>[2.0]</versionRangeSpec>",
                    "          <vulnerableClasses>",
                    "            <vulnerableClass>org.example.TrimmedCandidate</vulnerableClass>",
                    "          </vulnerableClasses>",
                    "          <sourceAdvisoryUrl>https://example.test/commit/abc123?diff=split&amp;w=1</sourceAdvisoryUrl>",
                    "          <confidenceLevel>HIGH</confidenceLevel>",
                    "        </vulnerabilityMapping>",
                    "      </vulnerabilityMappings>"),
        () ->
            assertThat(rendered)
                .noneMatch(
                    line -> line.startsWith("  - GHSA-heuristic org.example:trimmed:jar:2.0")),
        () ->
            assertThat(
                    rendered.stream()
                        .filter(
                            line -> line.startsWith("    Heuristic candidates are review leads;"))
                        .count())
                .isEqualTo(1L),
        () ->
            assertThat(
                    rendered.stream()
                        .filter("    POM mapping template for this candidate:"::equals)
                        .count())
                .isEqualTo(2L),
        () ->
            assertThat(rendered)
                .noneMatch(
                    line ->
                        line.contains("Verify the source claim and exact original artifact")
                            || line.startsWith("    If you verify this is the complete")));
  }

  @Test
  void typedRowsRejectApplicabilityAndHeuristicOwnerContradictions() {
    assertAll(
        "invalid in-memory rows cannot be written as reports",
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.PackageAdvisoryFinding(
                            "GHSA-package",
                            List.of(),
                            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
                            MAVEN_ECOSYSTEM,
                            GROUP_ID + ":removed",
                            List.of(VERSION),
                            List.of(),
                            OsvPackageApplicability.Status.NOT_APPLICABLE,
                            "contradictory status",
                            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
                            null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("applicability conflicts with raw OSV claims"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
                            "GHSA-owner",
                            List.of(CVE_ALIAS),
                            "CVE-2026-99999",
                            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
                            MAVEN_ECOSYSTEM,
                            GROUP_ID + ":removed",
                            "[1.0,2.0)",
                            OsvPackageApplicability.Status.UNRESOLVED,
                            "raw scope is unknown",
                            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
                            EvidenceOrigin.DESCRIPTION,
                            "GHSA-owner#description:0",
                            null,
                            null,
                            ConfidenceLevel.MEDIUM,
                            List.of(CANDIDATE_CLASS),
                            List.of(GROUP_ID + ":removed")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CVE must identify its OSV record or alias"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.AdvisoryReview(
                            List.of(heuristicPackageOwner()),
                            List.of(
                                heuristicFinding(
                                    CANDIDATE_CLASS, OsvPackageApplicability.Status.UNRESOLVED))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("conflicts with its unique OSV package owner"),
        () ->
            assertThatThrownBy(
                    () ->
                        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
                            "GHSA-owner",
                            List.of(CVE_ALIAS),
                            null,
                            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
                            MAVEN_ECOSYSTEM,
                            "other:artifact",
                            "unresolved",
                            OsvPackageApplicability.Status.UNRESOLVED,
                            "raw scope is unknown",
                            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
                            EvidenceOrigin.DESCRIPTION,
                            "GHSA-owner#description:0",
                            null,
                            null,
                            ConfidenceLevel.MEDIUM,
                            List.of(CANDIDATE_CLASS),
                            List.of("other:artifact")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("package advisory identity conflicts with coordinate"));
  }

  @Test
  void metadataDifferencesKeepSameRawPackageOwnersAmbiguousAcrossReportRoundTrip()
      throws IOException {
    final String osvId = "GHSA-metadata-owner";
    final ArtifactCoordinate coordinate = coordinate(REMOVED_ARTIFACT, VERSION);
    final String packageName = GROUP_ID + ":" + REMOVED_ARTIFACT;
    final MavenElisionReportSnapshot.PackageAdvisoryFinding firstPackage =
        packageFinding(osvId, coordinate, packageName, "a".repeat(64));
    final MavenElisionReportSnapshot.PackageAdvisoryFinding secondPackage =
        packageFinding(osvId, coordinate, packageName, "b".repeat(64));
    final MavenElisionReportSnapshot.HeuristicAdvisoryFinding heuristic =
        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
            osvId,
            List.of(CVE_ALIAS),
            CVE_ALIAS,
            coordinate.toString(),
            MAVEN_ECOSYSTEM,
            packageName,
            "unknown",
            OsvPackageApplicability.Status.UNRESOLVED,
            "Multiple matching raw package rows remain ambiguous",
            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
            EvidenceOrigin.DESCRIPTION,
            osvId + "#description:0",
            null,
            null,
            ConfidenceLevel.MEDIUM,
            List.of(CANDIDATE_CLASS),
            List.of(packageName));
    final MavenElisionReportSnapshot populated =
        snapshot()
            .withAdvisoryReview(
                new MavenElisionReportSnapshot.AdvisoryReview(
                    List.of(firstPackage, secondPackage), List.of(heuristic)));
    final Path output = temporaryDirectory.resolve("same-raw-package-owner-report.json");

    MavenElisionReportWriter.write(output, populated);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(output);

    assertAll(
        "metadata-distinct rows with identical raw claims remain ambiguous in saved reports",
        () -> assertThat(reread).isEqualTo(populated),
        () -> assertThat(reread.advisoryReview().packageAdvisories()).hasSize(2),
        () ->
            assertThat(reread.advisoryReview().heuristicAdvisories().getFirst().applicability())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED));
  }

  @Test
  void acceptsRepositoryQualifiedMavenEcosystemForTypedAndPersistedRows() throws IOException {
    final String repositoryEcosystem = "Maven:https://maven.google.com";
    final String packageName = GROUP_ID + ":" + REMOVED_ARTIFACT;
    final MavenElisionReportSnapshot.PackageAdvisoryFinding packageFinding =
        new MavenElisionReportSnapshot.PackageAdvisoryFinding(
            "GHSA-qualified-maven",
            List.of(CVE_ALIAS),
            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
            repositoryEcosystem,
            packageName,
            List.of(VERSION),
            List.of(),
            OsvPackageApplicability.Status.APPLICABLE,
            EXACT_VERSION_RATIONALE,
            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
            null);
    final MavenElisionReportSnapshot.HeuristicAdvisoryFinding heuristic =
        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
            "GHSA-qualified-maven",
            List.of(CVE_ALIAS),
            CVE_ALIAS,
            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
            repositoryEcosystem,
            packageName,
            "unknown",
            OsvPackageApplicability.Status.APPLICABLE,
            EXACT_VERSION_RATIONALE,
            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
            EvidenceOrigin.DESCRIPTION,
            "GHSA-qualified-maven#description:0",
            null,
            null,
            ConfidenceLevel.MEDIUM,
            List.of(CANDIDATE_CLASS),
            List.of(packageName));
    final MavenElisionReportSnapshot populated =
        snapshot()
            .withAdvisoryReview(
                new MavenElisionReportSnapshot.AdvisoryReview(
                    List.of(packageFinding), List.of(heuristic)));
    final Path output = temporaryDirectory.resolve("repository-qualified-maven-report.json");

    MavenElisionReportWriter.write(output, populated);

    assertThat(MavenElisionReportWriter.read(output)).isEqualTo(populated);
  }

  private MavenElisionReportSnapshot.AdvisoryReview advisoryReview() {
    final MavenElisionReportSnapshot.PackageAdvisoryFinding packageFinding =
        new MavenElisionReportSnapshot.PackageAdvisoryFinding(
            "GHSA-package-only",
            List.of(),
            coordinate(REMOVED_ARTIFACT, VERSION).toString(),
            MAVEN_ECOSYSTEM,
            GROUP_ID + ":" + REMOVED_ARTIFACT,
            List.of(),
            List.of(
                new MavenElisionReportSnapshot.AffectedRange(
                    "GIT",
                    "https://example.test/repo",
                    List.of(Map.of("zField", "z", "aField", "a")))),
            OsvPackageApplicability.Status.UNRESOLVED,
            "GIT ranges are not evaluated by this report",
            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
            null);
    final MavenElisionReportSnapshot.HeuristicAdvisoryFinding heuristicFinding =
        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
            "GHSA-heuristic",
            List.of(CVE_ALIAS),
            CVE_ALIAS,
            coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
            MAVEN_ECOSYSTEM,
            GROUP_ID + ":" + TRIMMED_ARTIFACT,
            "[2.0,3.0)",
            OsvPackageApplicability.Status.APPLICABLE,
            "Exact OSV version claim applies",
            MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
            EvidenceOrigin.REFERENCE_URL,
            "GHSA-heuristic#reference:0",
            "https://example.test/commit/abc123?diff=split&w=1",
            "a".repeat(64),
            ConfidenceLevel.MEDIUM,
            List.of("org.example.TrimmedCandidate"),
            List.of(GROUP_ID + ":" + TRIMMED_ARTIFACT));
    final MavenElisionReportSnapshot.HeuristicAdvisoryFinding secondHeuristicFinding =
        new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
            "GHSA-heuristic",
            List.of(CVE_ALIAS),
            CVE_ALIAS,
            coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
            MAVEN_ECOSYSTEM,
            GROUP_ID + ":" + TRIMMED_ARTIFACT,
            "[2.0,3.0)",
            OsvPackageApplicability.Status.APPLICABLE,
            "Exact OSV version claim applies",
            MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
            EvidenceOrigin.DESCRIPTION,
            "GHSA-heuristic#description:0",
            "https://example.test/description",
            "c".repeat(64),
            ConfidenceLevel.MEDIUM,
            List.of("org.example.SecondTrimmedCandidate"),
            List.of(GROUP_ID + ":" + TRIMMED_ARTIFACT));
    final MavenElisionReportSnapshot.PackageAdvisoryFinding heuristicOwner =
        new MavenElisionReportSnapshot.PackageAdvisoryFinding(
            "GHSA-heuristic",
            List.of(CVE_ALIAS),
            coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
            MAVEN_ECOSYSTEM,
            GROUP_ID + ":" + TRIMMED_ARTIFACT,
            List.of(SECOND_VERSION),
            List.of(),
            OsvPackageApplicability.Status.APPLICABLE,
            EXACT_VERSION_RATIONALE,
            MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
            "b".repeat(64));
    return new MavenElisionReportSnapshot.AdvisoryReview(
        List.of(packageFinding, heuristicOwner), List.of(heuristicFinding, secondHeuristicFinding));
  }

  private MavenElisionReportSnapshot.PackageAdvisoryFinding packageFinding(
      final String osvId,
      final ArtifactCoordinate coordinate,
      final String packageName,
      final String sourceDigest) {
    return new MavenElisionReportSnapshot.PackageAdvisoryFinding(
        osvId,
        List.of(CVE_ALIAS),
        coordinate.toString(),
        MAVEN_ECOSYSTEM,
        packageName,
        List.of(VERSION),
        List.of(),
        OsvPackageApplicability.Status.APPLICABLE,
        EXACT_VERSION_RATIONALE,
        MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
        sourceDigest);
  }

  private MavenElisionReportSnapshot.PackageAdvisoryFinding heuristicPackageOwner() {
    return new MavenElisionReportSnapshot.PackageAdvisoryFinding(
        "GHSA-heuristic-order",
        List.of(CVE_ALIAS),
        coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
        MAVEN_ECOSYSTEM,
        GROUP_ID + ":" + TRIMMED_ARTIFACT,
        List.of(SECOND_VERSION),
        List.of(),
        OsvPackageApplicability.Status.APPLICABLE,
        EXACT_VERSION_RATIONALE,
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
        null);
  }

  private MavenElisionReportSnapshot.HeuristicAdvisoryFinding heuristicFinding(
      final String candidateClass, final OsvPackageApplicability.Status applicability) {
    return new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
        "GHSA-heuristic-order",
        List.of(CVE_ALIAS),
        CVE_ALIAS,
        coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
        MAVEN_ECOSYSTEM,
        GROUP_ID + ":" + TRIMMED_ARTIFACT,
        "[1.0,3.0)",
        applicability,
        EXACT_VERSION_RATIONALE,
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
        EvidenceOrigin.REFERENCE_URL,
        "GHSA-heuristic-order#reference:0",
        "https://example.test/source",
        null,
        ConfidenceLevel.MEDIUM,
        List.of(candidateClass),
        List.of(GROUP_ID + ":" + TRIMMED_ARTIFACT));
  }

  private MavenElisionReportSnapshot snapshot() throws IOException {
    final ArtifactCoordinate removed = coordinate(REMOVED_ARTIFACT, VERSION);
    final ArtifactCoordinate trimmed = coordinate(TRIMMED_ARTIFACT, SECOND_VERSION);
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        GROUP_ID,
        "consumer",
        VERSION,
        temporaryDirectory.toString(),
        GENERATED_AT,
        new TrimExecutionEnvironment(21, Runtime.version().feature()),
        1,
        2048,
        2,
        18,
        List.of(new MavenElisionReportSnapshot.DroppedArtifact(removed.toString(), 2048, 2, 18)),
        List.of(removed.toString()),
        4,
        3096,
        List.of(new MavenElisionReportSnapshot.TrimmedArtifact(trimmed.toString(), 4, 3096)),
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        MediatedGraphReportTestSupport.reportForOutputs(
            removed, trimmed, GROUP_ID + ":consumer:" + VERSION),
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }

  private static ArtifactCoordinate coordinate(final String artifact, final String version) {
    return ArtifactCoordinate.of(GROUP_ID, artifact, version);
  }
}
