// WHY: Keeps total-order report assertions separate from advisory payload validation tests.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ConfidenceLevel;
import io.github.spockz.elider.model.EvidenceOrigin;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies stable advisory ordering when report input rows are permuted. */
final class MavenElisionReportAdvisoryOrderingTest {
  /** Shared synthetic artifact group. */
  private static final String GROUP_ID = "org.example";

  /** Stable version for fixture coordinates. */
  private static final String VERSION = "1.0";

  /** Second stable version used in heuristic scope fixtures. */
  private static final String SECOND_VERSION = "2.0";

  /** CVE aliases used to distinguish heuristic row keys. */
  private static final String CVE_ALIAS = "CVE-2026-12345";

  /** Second CVE alias used to test nullable-value ordering. */
  private static final String SECOND_CVE_ALIAS = "CVE-2026-54321";

  /** Candidate class used by the ordering fixtures. */
  private static final String CANDIDATE_CLASS = "org.example.Candidate";

  /** Owner record shared by heuristic rows. */
  private static final String OSV_ID = "GHSA-heuristic-order";

  /** URLs used to distinguish heuristic report rows. */
  private static final String SOURCE_URL_A = "https://example.test/source-a";

  /** Second source URL used to distinguish heuristic row keys. */
  private static final String SOURCE_URL_B = "https://example.test/source-b";

  /** Artifact identifiers used by ordering fixtures. */
  private static final String REMOVED_ARTIFACT = "removed";

  /** Artifact identifier used by heuristic owner fixtures. */
  private static final String TRIMMED_ARTIFACT = "trimmed";

  /** Stable ecosystem and rationale for exact-version fixture claims. */
  private static final String MAVEN_ECOSYSTEM = "Maven";

  /** Exact-version rationale used by package owner fixtures. */
  private static final String EXACT_VERSION_RATIONALE =
      "Exact version is listed by the OSV affected package";

  /** Isolated report output directory. */
  @TempDir private Path temporaryDirectory;

  /** Creates this JUnit fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenElisionReportAdvisoryOrderingTest() {}

  @Test
  void advisoryReviewOrderingIsTotalAndStableForReversedInputs() throws IOException {
    final MavenElisionReportSnapshot.PackageAdvisoryFinding firstPackage =
        orderedPackageFinding(List.of(VERSION), "a".repeat(64));
    final MavenElisionReportSnapshot.PackageAdvisoryFinding secondPackage =
        orderedPackageFinding(List.of(VERSION, "1.1"), "b".repeat(64));
    final MavenElisionReportSnapshot.PackageAdvisoryFinding heuristicOwner =
        orderedHeuristicPackageOwner();
    final List<MavenElisionReportSnapshot.HeuristicAdvisoryFinding> orderedHeuristics =
        List.of(
            orderedHeuristicFinding(CVE_ALIAS, SOURCE_URL_A, "a".repeat(64), CANDIDATE_CLASS),
            orderedHeuristicFinding(CVE_ALIAS, SOURCE_URL_A, "b".repeat(64), CANDIDATE_CLASS),
            orderedHeuristicFinding(CVE_ALIAS, SOURCE_URL_B, "a".repeat(64), CANDIDATE_CLASS),
            orderedHeuristicFinding(
                SECOND_CVE_ALIAS, SOURCE_URL_A, "a".repeat(64), CANDIDATE_CLASS),
            orderedHeuristicFinding(
                CVE_ALIAS, SOURCE_URL_A, "a".repeat(64), "org.example.ZCandidate"));
    final MavenElisionReportSnapshot.AdvisoryReview forward =
        new MavenElisionReportSnapshot.AdvisoryReview(
            List.of(firstPackage, heuristicOwner, secondPackage), orderedHeuristics);
    final MavenElisionReportSnapshot.AdvisoryReview reverse =
        new MavenElisionReportSnapshot.AdvisoryReview(
            List.of(secondPackage, heuristicOwner, firstPackage), orderedHeuristics.reversed());
    final Path first = temporaryDirectory.resolve("advisory-forward.json");
    final Path second = temporaryDirectory.resolve("advisory-reverse.json");
    final MavenElisionReportSnapshot firstSnapshot = snapshot().withAdvisoryReview(forward);
    final MavenElisionReportSnapshot secondSnapshot = snapshot().withAdvisoryReview(reverse);

    MavenElisionReportWriter.write(first, firstSnapshot);
    MavenElisionReportWriter.write(second, secondSnapshot);

    assertAll(
        "full row keys determine stable report order without reordering OSV events",
        () -> assertThat(Files.readAllBytes(first)).containsExactly(Files.readAllBytes(second)),
        () ->
            assertThat(MavenElisionReportWriter.render(firstSnapshot))
                .containsExactlyElementsOf(MavenElisionReportWriter.render(secondSnapshot)),
        () ->
            assertThat(MavenElisionReportWriter.render(firstSnapshot))
                .contains(
                    "    OSV ranges: [AffectedRange[type=GIT, repo=https://example.test/repo,"
                        + " events=[{aField=first, zField=last}, {introduced=1.0}]]]"),
        () ->
            assertThat(firstSnapshot.advisoryReview().packageAdvisories())
                .extracting(MavenElisionReportSnapshot.PackageAdvisoryFinding::affectedVersions)
                .containsExactly(
                    List.of(VERSION), List.of(VERSION, "1.1"), List.of(SECOND_VERSION)),
        () ->
            assertThat(firstSnapshot.advisoryReview().heuristicAdvisories())
                .extracting(MavenElisionReportSnapshot.HeuristicAdvisoryFinding::cveId)
                .containsExactly(CVE_ALIAS, CVE_ALIAS, CVE_ALIAS, CVE_ALIAS, SECOND_CVE_ALIAS),
        () ->
            assertThat(firstSnapshot.advisoryReview().heuristicAdvisories())
                .extracting(MavenElisionReportSnapshot.HeuristicAdvisoryFinding::sourceUrl)
                .containsExactly(
                    SOURCE_URL_A, SOURCE_URL_A, SOURCE_URL_A, SOURCE_URL_B, SOURCE_URL_A),
        () ->
            assertThat(firstSnapshot.advisoryReview().heuristicAdvisories())
                .extracting(MavenElisionReportSnapshot.HeuristicAdvisoryFinding::sourceRecordSha256)
                .containsExactly(
                    "a".repeat(64), "a".repeat(64), "b".repeat(64), "a".repeat(64), "a".repeat(64)),
        () ->
            assertThat(firstSnapshot.advisoryReview().heuristicAdvisories())
                .extracting(MavenElisionReportSnapshot.HeuristicAdvisoryFinding::candidateClasses)
                .containsExactly(
                    List.of(CANDIDATE_CLASS),
                    List.of("org.example.ZCandidate"),
                    List.of(CANDIDATE_CLASS),
                    List.of(CANDIDATE_CLASS),
                    List.of(CANDIDATE_CLASS)));
  }

  private MavenElisionReportSnapshot.PackageAdvisoryFinding orderedPackageFinding(
      final List<String> versions, final String digest) {
    return new MavenElisionReportSnapshot.PackageAdvisoryFinding(
        "GHSA-package-order",
        List.of(),
        coordinate(REMOVED_ARTIFACT, VERSION).toString(),
        MAVEN_ECOSYSTEM,
        GROUP_ID + ":" + REMOVED_ARTIFACT,
        versions,
        List.of(
            new MavenElisionReportSnapshot.AffectedRange(
                "GIT",
                "https://example.test/repo",
                List.of(
                    Map.of("zField", "last", "aField", "first"), Map.of("introduced", VERSION)))),
        OsvPackageApplicability.Status.APPLICABLE,
        EXACT_VERSION_RATIONALE,
        MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
        digest);
  }

  private MavenElisionReportSnapshot.PackageAdvisoryFinding orderedHeuristicPackageOwner() {
    return new MavenElisionReportSnapshot.PackageAdvisoryFinding(
        OSV_ID,
        List.of(CVE_ALIAS, SECOND_CVE_ALIAS),
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

  private MavenElisionReportSnapshot.HeuristicAdvisoryFinding orderedHeuristicFinding(
      final String cveId,
      final String sourceUrl,
      final String digest,
      final String candidateClass) {
    return new MavenElisionReportSnapshot.HeuristicAdvisoryFinding(
        OSV_ID,
        List.of(CVE_ALIAS, SECOND_CVE_ALIAS),
        cveId,
        coordinate(TRIMMED_ARTIFACT, SECOND_VERSION).toString(),
        MAVEN_ECOSYSTEM,
        GROUP_ID + ":" + TRIMMED_ARTIFACT,
        "[1.0,3.0)",
        OsvPackageApplicability.Status.APPLICABLE,
        EXACT_VERSION_RATIONALE,
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
        EvidenceOrigin.REFERENCE_URL,
        OSV_ID + "#reference:0",
        sourceUrl,
        digest,
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
        "2026-10-26T16:00:00Z",
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
