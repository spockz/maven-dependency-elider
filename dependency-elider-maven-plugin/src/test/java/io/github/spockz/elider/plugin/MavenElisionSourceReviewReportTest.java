// WHY: Verifies saved source-review claims remain historical report data, not live assessment.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers serialization and rendering of review-only source findings. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class MavenElisionSourceReviewReportTest {
  /** Stable timestamp used to verify historical report rendering. */
  private static final String GENERATED_AT = "2026-10-26T16:00:00Z";

  /** Temporary directory for generated report snapshots. */
  @TempDir private Path temporaryDirectory;

  @Test
  void sourceReviewRowsRoundTripBothSavedFlagsAndRenderHistoricalSnapshot() throws IOException {
    final MavenElisionReportSnapshot falseSnapshot = sourceReviewSnapshot(false);
    final MavenElisionReportSnapshot trueSnapshot = sourceReviewSnapshot(true);
    final Path falseReport = temporaryDirectory.resolve("source-review-false.json");
    final Path trueReport = temporaryDirectory.resolve("source-review-true.json");

    MavenElisionReportWriter.write(falseReport, falseSnapshot);
    MavenElisionReportWriter.write(trueReport, trueSnapshot);
    final MavenElisionReportSnapshot falseReread = MavenElisionReportWriter.read(falseReport);
    final MavenElisionReportSnapshot trueReread = MavenElisionReportWriter.read(trueReport);

    assertAll(
        "the report preserves source-review claims and saved assumption without reassessment",
        () -> assertThat(falseReread).isEqualTo(falseSnapshot),
        () -> assertThat(trueReread).isEqualTo(trueSnapshot),
        () -> assertThat(falseReread.sourceReviewFindings().getFirst().matches()).hasSize(1),
        () -> assertThat(trueReread.sourceReviewFindings().getFirst().programRoutines()).isEmpty(),
        () ->
            assertThat(MavenElisionReportWriter.render(trueReread))
                .contains(
                    "Snapshot: last successful elide run at " + GENERATED_AT,
                    "Conventional Java source layout assumption saved for this run: true",
                    "Structured source claims (review only; "
                        + "verify before configuring a POM mapping):",
                    "  - OSV GHSA-example CVE-2025-11226 org.example:demo:jar:1.0 (compile) "
                        + "[containers.cna.affected[1]]",
                    "    SourceFile match leads:",
                    "    Verify the complete source-to-class mapping, then add an exact POM"
                        + " vulnerableClasses assertion if confirmed; a filename match alone is"
                        + " incomplete."));
  }

  @Test
  void assessmentSourceClaimsFlowThroughSnapshotWriterAndReader() throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepare(temporaryDirectory.resolve("assessment"));
    final MavenVulnerabilityAssessment.Result assessment =
        MavenCorroboratedSourceScenario.assessWithLayoutFlag(scenario, true, true);
    final ElisionAnalysisModel.Analysis analysis =
        MavenCorroboratedSourceAnalysisFixtures.analysis(
            scenario.coordinate(),
            scenario.originalJar(),
            List.of(scenario.successfulTrimRecord()),
            false,
            false);
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("assessment-project");
    project.setVersion("1.0");
    project.setFile(temporaryDirectory.resolve("assessment/pom.xml").toFile());
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(project, analysis, assessment);
    final Path report = temporaryDirectory.resolve("assessment-report.json");
    MavenElisionReportWriter.write(report, snapshot);
    final MavenElisionReportSnapshot restored = MavenElisionReportWriter.read(report);
    final boolean restoredAssumption = restored.assumeConventionalJavaSourceLayout();

    assertAll(
        "live assessment source claims are persisted as historical report rows",
        () -> assertThat(assessment.matchedSourceClaims()).hasSize(1),
        () -> assertThat(restored).isEqualTo(snapshot),
        () -> assertTrue(restoredAssumption, "the saved report retains its historical flag"),
        () -> assertThat(restored.sourceReviewFindings()).hasSize(1),
        () ->
            assertThat(restored.sourceReviewFindings().getFirst().matches())
                .isNotEmpty()
                .allSatisfy(
                    match ->
                        assertThat(match.originalArchiveSha256())
                            .isEqualTo(scenario.originalDigest().sha256())));
  }

  @Test
  void ambiguousCnaProductsRemainUnresolvedReportRowsWithoutProof() {
    assertAll(
        "product entry order cannot select a CNA owner",
        () -> assertAmbiguousProducts(temporaryDirectory.resolve("ambiguous-products"), false),
        () -> assertAmbiguousProducts(temporaryDirectory.resolve("reversed-products"), true));
  }

  private void assertAmbiguousProducts(final Path directory, final boolean reverse)
      throws IOException {
    final MavenCorroboratedSourceScenario.Prepared scenario =
        MavenCorroboratedSourceScenario.prepareAmbiguousProductClaim(directory, reverse);
    final MavenVulnerabilityAssessment.Result assessment = scenario.result();
    final ElisionAnalysisModel.Analysis analysis =
        MavenCorroboratedSourceAnalysisFixtures.analysis(
            scenario.coordinate(),
            scenario.originalJar(),
            List.of(scenario.successfulTrimRecord()),
            false,
            false);
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("assessment-project");
    project.setVersion("1.0");
    project.setFile(directory.resolve("pom.xml").toFile());
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(project, analysis, assessment);
    final Path report = directory.resolve("report.json");
    MavenElisionReportWriter.write(report, snapshot);
    final MavenElisionReportSnapshot restored = MavenElisionReportWriter.read(report);

    assertAll(
        "multiple exact CNA product entries remain unresolved review rows",
        () -> assertThat(assessment.matchedSourceClaims()).hasSize(2),
        () -> assertThat(MavenCorroboratedSourceScenario.candidates(assessment)).isEmpty(),
        () -> assertThat(assessment.attestations()).isEmpty(),
        () -> assertThat(assessment.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(assessment.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(assessment.potentiallyConservativeCves()).isEmpty(),
        () -> assertThat(assessment.removedComponents()).isEmpty(),
        () -> assertThat(snapshot.sourceReviewFindings()).hasSize(2),
        () -> assertThat(restored).isEqualTo(snapshot),
        () ->
            assertThat(restored.sourceReviewFindings())
                .allSatisfy(
                    finding ->
                        assertThat(finding.applicability())
                            .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED)));
  }

  private static MavenElisionReportSnapshot sourceReviewSnapshot(final boolean assumed)
      throws IOException {
    final MavenElisionReportSnapshot.SourceReviewFinding finding =
        new MavenElisionReportSnapshot.SourceReviewFinding(
            "GHSA-example",
            "CVE-2025-11226",
            "org.example:demo:jar:1.0 (compile)",
            "a".repeat(64),
            "containers.cna.affected[1]",
            "Example demo",
            List.of("src/main/java/org/example/Outer.java"),
            List.of(),
            assumed,
            List.of(
                new MavenElisionReportSnapshot.SourceReviewMatch(
                    "src/main/java/org/example/Outer.java",
                    "org/example/Outer.class",
                    0,
                    "org.example.Outer",
                    "Outer.java",
                    "source path package suffix matches class package org.example; exact source "
                        + "location and sibling class set remain unverified "
                        + "(src/main/java/org/example/Outer.java)",
                    "b".repeat(64))),
            OsvPackageApplicability.Status.APPLICABLE,
            "OSV and the exact CNA product entry both mark the version affected",
            "SourceFile matches are review leads only; verify the complete source-unit class set.");
    return new MavenElisionReportSnapshot(
        MavenElisionReportSnapshot.SCHEMA_VERSION,
        "org.example",
        "consumer",
        "1.0",
        "/tmp/report-project",
        GENERATED_AT,
        new TrimExecutionEnvironment(21, Runtime.version().feature()),
        0,
        0L,
        0,
        0L,
        List.of(),
        List.of(),
        0,
        0L,
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        List.of(),
        MediatedGraphReportTestSupport.emptyGraph("org.example:consumer:1.0"),
        assumed,
        List.of(finding),
        MavenElisionPolicyIdentityTestSupport.emptyPolicy());
  }
}
