// WHY: Proves raw OSV version claims control heuristic report applicability.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies raw OSV applicability separately from heuristic candidate scope. */
final class MavenHeuristicApplicabilityTest {
  /** Isolated cache and assessment workspace. */
  /* package */
  @TempDir Path temporaryDirectory;

  /** Creates the isolated test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenHeuristicApplicabilityTest() {}

  @Test
  void exactAffectedVersionRetainsHeuristicWhenFlattenedRangeDisagrees() throws IOException {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final Path cacheDirectory = temporaryDirectory.resolve("exact-version-disjoint-range-cache");
    MavenAssessmentFixtures.writeCacheDocument(
        cacheDirectory, MavenAssessmentFixtures.exactVersionDisjointRangeCache(coordinate));
    final VulnerabilityCacheManager.CacheConfig cacheConfig =
        new VulnerabilityCacheManager.CacheConfig(
            cacheDirectory,
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);

    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(cacheConfig, List.of(), List.of(), List.of(), List.of(coordinate));

    assertAll(
        "raw exact OSV version controls review applicability despite a disjoint flattened scope",
        () -> assertThat(result.heuristicAdvisoryFindings()).hasSize(1),
        () ->
            assertThat(result.heuristicAdvisoryFindings().getFirst().applicability())
                .isEqualTo(OsvPackageApplicability.Status.APPLICABLE),
        () ->
            assertThat(result.heuristicAdvisoryFindings().getFirst().applicabilityRationale())
                .contains("Exact version is listed"),
        () -> assertThat(result.packageAdvisoryFindings()).hasSize(1),
        () -> assertThat(result.attestations()).isEmpty(),
        () -> assertThat(result.provenVulnerableCodeAbsent()).isEmpty(),
        () -> assertThat(result.inactiveDueToMissingPrerequisites()).isEmpty(),
        () -> assertThat(result.potentiallyConservativeCves()).isEmpty());
  }

  @Test
  void assessmentSnapshotRoundTripPreservesDistinctAmbiguousRawPackageOwners() throws IOException {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final Path cacheDirectory = temporaryDirectory.resolve("ambiguous-package-owner-cache");
    MavenAssessmentFixtures.writeCacheDocument(
        cacheDirectory, MavenAssessmentFixtures.ambiguousSameStatusPackageOwnerCache(coordinate));
    final VulnerabilityCacheManager.CacheConfig cacheConfig =
        new VulnerabilityCacheManager.CacheConfig(
            cacheDirectory,
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(cacheConfig, List.of(), List.of(), List.of(), List.of(coordinate));
    final MavenElisionReportSnapshot snapshot =
        new MavenElisionReportSnapshot(
                MavenElisionReportSnapshot.SCHEMA_VERSION,
                "org.example",
                "consumer",
                "1.0",
                temporaryDirectory.toString(),
                "2026-11-01T00:00:00Z",
                0,
                0,
                List.of(),
                List.of(),
                0,
                0,
                List.of(),
                MediatedGraphReport.unavailable("test"))
            .withAdvisoryReview(MavenElisionReportSnapshot.advisoryReview(result));
    final Path reportPath = temporaryDirectory.resolve("ambiguous-package-owner-report.json");

    MavenElisionReportWriter.write(reportPath, snapshot);
    final MavenElisionReportSnapshot reread = MavenElisionReportWriter.read(reportPath);

    assertAll(
        "distinct raw OSV package owners remain ambiguous through the report round trip",
        () -> assertThat(result.packageAdvisoryFindings()).hasSize(2),
        () ->
            assertThat(result.packageAdvisoryFindings())
                .extracting(MavenVulnerabilityAssessment.PackageAdvisoryFinding::applicability)
                .containsOnly(OsvPackageApplicability.Status.APPLICABLE),
        () -> assertThat(result.heuristicAdvisoryFindings()).hasSize(1),
        () ->
            assertThat(result.heuristicAdvisoryFindings().getFirst().applicability())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED),
        () -> assertThat(reread).isEqualTo(snapshot));
  }
}
