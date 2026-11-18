// WHY: Proves trim identity and source paths are rejected before publication changes reports.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.advisory.VulnerabilityCacheManager;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired", "PMD.LawOfDemeter"})
final class MavenElisionOutputPublisherBanBoundaryTest {
  private static final String BAN = "fixture:banned";
  private static final String PREVIOUS_REPORT = "prior report\n";
  private static final String PREVIOUS_SUMMARY = "prior summary\n";

  @TempDir private Path temporaryDirectory;

  @Test
  void trimSourcePathMismatchFailsBeforeReportPublication() throws Exception {
    final NoExtensionAnalyzeBanPredictionTest.Fixture fixture =
        NoExtensionAnalyzeBanPredictionTest.publicationFixture(temporaryDirectory);
    final org.apache.maven.artifact.Artifact used =
        fixture.project().getArtifacts().stream()
            .filter(artifact -> "used".equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    NoExtensionAnalyzeBanPredictionTest.addClassToJar(used.getFile().toPath(), "used/Unused");
    final Path wrongOriginal = temporaryDirectory.resolve("wrong-original.jar");
    Files.copy(used.getFile().toPath(), wrongOriginal);
    final Path report = temporaryDirectory.resolve("path-mismatch-report.json");
    final Path summary = temporaryDirectory.resolve("path-mismatch-summary.json");
    Files.writeString(report, PREVIOUS_REPORT);
    Files.writeString(summary, PREVIOUS_SUMMARY);
    final List<org.apache.maven.artifact.Artifact> resolvedView =
        List.copyOf(fixture.project().getArtifacts());
    final List<org.apache.maven.artifact.Artifact> directView =
        List.copyOf(fixture.project().getDependencyArtifacts());
    final Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles =
        artifactFiles(resolvedView, directView);
    final Object priorResolverPlan = new Object();
    fixture
        .repositorySession()
        .getData()
        .set(ResolverArtifactPlanPublisher.SESSION_DATA_KEY, priorResolverPlan);
    final Exception failure =
        publishWithMalformedTrim(fixture, report, summary, wrongOriginal, false);

    assertThat(failure).hasMessageContaining("Artifact path changed before applying trim");
    assertAll(
        "trim source identity is validated before output replacement",
        () -> assertThat(report).hasContent(PREVIOUS_REPORT),
        () -> assertThat(summary).hasContent(PREVIOUS_SUMMARY),
        () -> assertSameArtifactReferences(fixture.project().getArtifacts(), resolvedView),
        () -> assertSameArtifactReferences(fixture.project().getDependencyArtifacts(), directView),
        () -> assertThat(artifactFiles(resolvedView, directView)).isEqualTo(artifactFiles),
        () ->
            assertThat(
                    fixture
                        .repositorySession()
                        .getData()
                        .get(ResolverArtifactPlanPublisher.SESSION_DATA_KEY))
                .isSameAs(priorResolverPlan));
  }

  @Test
  void publicationGateRejectsTrimIdentityMissingFromResolvedPlan() throws Exception {
    final NoExtensionAnalyzeBanPredictionTest.Fixture fixture =
        NoExtensionAnalyzeBanPredictionTest.publicationFixture(temporaryDirectory);
    final org.apache.maven.artifact.Artifact used =
        fixture.project().getArtifacts().stream()
            .filter(artifact -> "used".equals(artifact.getArtifactId()))
            .findFirst()
            .orElseThrow();
    NoExtensionAnalyzeBanPredictionTest.addClassToJar(used.getFile().toPath(), "used/Unused");
    final Path report = temporaryDirectory.resolve("unmatched-trim-report.json");
    final Path summary = temporaryDirectory.resolve("unmatched-trim-summary.json");
    Files.writeString(report, PREVIOUS_REPORT);
    Files.writeString(summary, PREVIOUS_SUMMARY);
    final Exception failure = publishWithMalformedTrim(fixture, report, summary, null, true);

    assertThat(failure).hasMessageContaining("Trim records have no resolved Maven artifacts");
    assertAll(
        "every trim record must match the planned resolved view before output replacement",
        () -> assertThat(report).hasContent(PREVIOUS_REPORT),
        () -> assertThat(summary).hasContent(PREVIOUS_SUMMARY));
  }

  private static Exception publishWithMalformedTrim(
      final NoExtensionAnalyzeBanPredictionTest.Fixture fixture,
      final Path report,
      final Path summary,
      final Path wrongOriginalPath,
      final boolean addUnmatchedRecord)
      throws IOException, MojoFailureException {
    final MavenArtifactViewBinding.LiveSnapshot live =
        MavenArtifactViewBinding.capture(fixture.project());
    try (MavenBanPreparation preparation =
        MavenBanPreparation.prepare(
            fixture.project(), fixture.options(List.of(BAN), true), fixture.resolver())) {
      final MavenArtifactViewBinding binding =
          MavenArtifactViewBinding.bind(live, preparation.context());
      final MavenElisionService service = new MavenElisionService();
      final Analysis initial =
          binding.bindAnalysis(
              service.finishEffectiveOutputs(service.finishAnalysis(preparation.analysis())));
      final ElisionAnalysisModel.ApplyPlan validApplyPlan =
          MavenArtifactInventory.plan(fixture.project(), initial);
      if (addUnmatchedRecord) {
        MavenBanClassProviderClosure.verifyPublication(
            preparation.plan(),
            binding,
            validApplyPlan,
            initial,
            fixture.project(),
            fixture.session());
      }
      final List<ArtifactTrimRecord> records = new ArrayList<>(initial.trimResult().records());
      final ArtifactTrimRecord original = records.getFirst();
      if (wrongOriginalPath != null) {
        records.set(0, copyRecord(original, wrongOriginalPath));
      }
      if (addUnmatchedRecord) {
        final ArtifactCoordinate unmatched =
            new ArtifactCoordinate("fixture", "used", "2.0", "jar", "", "compile");
        records.set(0, copyRecord(original, unmatched));
      }
      final TrimResult trims =
          new TrimResult(
              records,
              initial.trimResult().multiReleasePassthroughArtifacts(),
              initial.trimResult().moduleInfoPassthroughArtifacts(),
              initial.trimResult().configuredPassThroughArtifacts(),
              initial.trimResult().cacheHits(),
              initial.trimResult().maximumCacheHitNanos(),
              initial.trimResult().analysisRuns(),
              initial.trimResult().executionEnvironment(),
              initial.trimResult().toleratedDuplicates());
      final Analysis malformed =
          new Analysis(
              initial.artifacts(),
              initial.decision(),
              initial.effectiveDecision(),
              initial.evidence(),
              trims,
              initial.graphProjection(),
              initial.mediatedGraph(),
              initial.policyIdentity(),
              initial.traceDecision(),
              initial.banPlan());
      if (addUnmatchedRecord) {
        try {
          MavenBanClassProviderClosure.verifyPublication(
              preparation.plan(),
              binding,
              validApplyPlan,
              malformed,
              fixture.project(),
              fixture.session());
          return null;
        } catch (final IOException | MojoFailureException failure) {
          return failure;
        }
      }
      final VulnerabilityCacheManager.CacheConfig cacheConfig =
          new VulnerabilityCacheManager.CacheConfig(
              report.getParent().resolve("cache"),
              null,
              null,
              Duration.ofHours(1),
              false,
              true,
              VulnerabilityCacheManager.bundledEmptySeed());
      try {
        MavenElisionOutputPublisher.publish(
            new MavenElisionOutputPublisher.Request(
                fixture.project(),
                fixture.session(),
                service,
                malformed,
                new MavenElisionOutputPublisher.ReportFiles(
                    report.toFile(),
                    report.resolveSibling("sbom.json").toFile(),
                    report.resolveSibling("baseline.json").toFile(),
                    report.resolveSibling("vex.json").toFile(),
                    summary.toFile(),
                    false),
                new SystemStreamLog(),
                (session, project, trimRecords, projection) -> {},
                cacheConfig,
                ConfiguredVulnerabilityMappings.empty(),
                SnykPackageIssuesIntegration.Configuration.disabled(),
                false,
                false,
                preparation.plan(),
                binding));
      } catch (final IOException | MojoFailureException failure) {
        return failure;
      }
    }
    throw new AssertionError("Malformed trim publication unexpectedly succeeded");
  }

  private static ArtifactTrimRecord copyRecord(
      final ArtifactTrimRecord source, final Path originalPath) {
    return copyRecord(source, source.coordinate(), originalPath);
  }

  private static ArtifactTrimRecord copyRecord(
      final ArtifactTrimRecord source, final ArtifactCoordinate coordinate) {
    return copyRecord(source, coordinate, source.originalPath());
  }

  private static ArtifactTrimRecord copyRecord(
      final ArtifactTrimRecord source,
      final ArtifactCoordinate coordinate,
      final Path originalPath) {
    return new ArtifactTrimRecord(
        coordinate,
        originalPath,
        source.originalSha256(),
        source.originalSha1(),
        source.trimmedPath(),
        source.trimmedSha256(),
        source.trimmedSha1(),
        source.totalClasses(),
        source.retainedClasses(),
        source.prunedClassBytes(),
        source.physicalEntryMetrics(),
        source.mrjarStatus());
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<org.apache.maven.artifact.Artifact, java.io.File> artifactFiles(
      final Iterable<org.apache.maven.artifact.Artifact> resolved,
      final Iterable<org.apache.maven.artifact.Artifact> direct) {
    final Map<org.apache.maven.artifact.Artifact, java.io.File> files = new IdentityHashMap<>();
    resolved.forEach(artifact -> files.put(artifact, artifact.getFile()));
    direct.forEach(artifact -> files.putIfAbsent(artifact, artifact.getFile()));
    return files;
  }

  private static void assertSameArtifactReferences(
      final Iterable<org.apache.maven.artifact.Artifact> actual,
      final List<org.apache.maven.artifact.Artifact> expected) {
    final List<org.apache.maven.artifact.Artifact> actualItems = new ArrayList<>();
    actual.forEach(actualItems::add);
    assertThat(actualItems).hasSameSizeAs(expected);
    for (int index = 0; index < expected.size(); index++) {
      assertThat(actualItems.get(index)).isSameAs(expected.get(index));
    }
  }
}
