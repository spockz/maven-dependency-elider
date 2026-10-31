// WHY: Assembles one cache-to-assessment path for source-corroboration behavior tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.scanner.OsvSnapshotIndexer;
import io.github.spockz.elider.scanner.VulnerabilityCacheEnvelopeWriter;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Shares setup between the proof-positive and review-only assertions. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenCorroboratedSourceScenario {
  record Prepared(
      VulnerabilityCacheManager.CacheConfig cacheConfig,
      ArtifactCoordinate coordinate,
      Path originalJar,
      String cveDigest,
      ArtifactDigests originalDigest,
      ArtifactTrimRecord successfulTrimRecord,
      MavenVulnerabilityAssessment.Result result) {}

  record AssessmentWithLog(MavenVulnerabilityAssessment.Result result, RecordingMavenLog log) {}

  private MavenCorroboratedSourceScenario() {}

  static Prepared prepare(final Path directory) throws IOException {
    final Path cveRecord = MavenCorroboratedSourceArchiveFixtures.writeCveRecord(directory);
    final String cveDigest = ArtifactDigests.read(cveRecord).sha256();
    final List<OsvAdvisoryRecord> indexedRecords =
        new OsvSnapshotIndexer()
            .indexZip(
                new ByteArrayInputStream(MavenCorroboratedSourceArchiveFixtures.osvSnapshot()),
                directory);
    final List<OsvAdvisoryRecord> records =
        List.of(
            MavenCorroboratedSourceCacheFixtures.withStaleCorroboratedCandidate(
                indexedRecords.getFirst()));
    final Path cacheDirectory = Files.createDirectories(directory.resolve("cache"));
    Files.write(
        cacheDirectory.resolve("index.json"),
        new VulnerabilityCacheEnvelopeWriter()
            .encode(MavenAssessmentFixtures.CACHE_PRODUCER, records));
    final Path originalJar =
        MavenCorroboratedSourceArchiveFixtures.writeOriginalJar(
            directory.resolve("original.jar"), false);
    final Path trimmedJar = directory.resolve("trimmed.jar");
    MavenCorroboratedSourceArchiveFixtures.writeTrimmedJar(trimmedJar);
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(
            MavenCorroboratedSourceArchiveFixtures.GROUP_ID,
            MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID,
            MavenCorroboratedSourceArchiveFixtures.VERSION);
    final ArtifactDigests originalDigest = ArtifactDigests.read(originalJar);
    final ArtifactDigests trimmedDigest = ArtifactDigests.read(trimmedJar);
    final ArtifactTrimRecord trimRecord =
        new ArtifactTrimRecord(
            coordinate,
            originalJar,
            originalDigest.sha256(),
            originalDigest.sha1(),
            trimmedJar,
            trimmedDigest.sha256(),
            trimmedDigest.sha1(),
            1,
            0,
            64);
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
    final RecordingMavenLog log = new RecordingMavenLog();
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(log)
            .assess(
                cacheConfig,
                ConfiguredVulnerabilityMappings.fromPom(List.of(pomAssertion())),
                analysis(coordinate, originalJar, List.of(trimRecord), false, false),
                null);
    return new Prepared(
        cacheConfig, coordinate, originalJar, cveDigest, originalDigest, trimRecord, result);
  }

  static MavenVulnerabilityAssessment.Result reassess(
      final Prepared prepared, final boolean removed, final boolean duplicateExactSnapshots)
      throws IOException {
    return new MavenVulnerabilityAssessment(new RecordingMavenLog())
        .assess(
            prepared.cacheConfig(),
            ConfiguredVulnerabilityMappings.empty(),
            analysis(
                prepared.coordinate(),
                prepared.originalJar(),
                List.of(),
                removed,
                duplicateExactSnapshots),
            null);
  }

  static MavenVulnerabilityAssessment.Result assessWithoutOwnerAssertions(final Prepared prepared)
      throws IOException {
    return new MavenVulnerabilityAssessment(new RecordingMavenLog())
        .assess(
            prepared.cacheConfig(),
            ConfiguredVulnerabilityMappings.empty(),
            analysis(
                prepared.coordinate(),
                prepared.originalJar(),
                List.of(prepared.successfulTrimRecord()),
                false,
                false),
            null);
  }

  static AssessmentWithLog reassessWithArchive(final Prepared prepared, final Path originalJar)
      throws IOException {
    final RecordingMavenLog log = new RecordingMavenLog();
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(log)
            .assess(
                prepared.cacheConfig(),
                ConfiguredVulnerabilityMappings.empty(),
                analysis(prepared.coordinate(), originalJar, List.of(), false, false),
                null);
    return new AssessmentWithLog(result, log);
  }

  static List<CorroboratedSourceClassCandidate> candidates(
      final MavenVulnerabilityAssessment.Result result) {
    return result.matchedAdvisoryEvidence().stream()
        .map(MavenVulnerabilityAssessment.MatchedAdvisoryEvidence::evidence)
        .filter(CorroboratedSourceClassCandidate.class::isInstance)
        .map(CorroboratedSourceClassCandidate.class::cast)
        .toList();
  }

  private static ElisionAnalysisModel.Analysis analysis(
      final ArtifactCoordinate coordinate,
      final Path originalJar,
      final List<ArtifactTrimRecord> trimRecords,
      final boolean removed,
      final boolean duplicateExactSnapshots) {
    final ElisionDecision decision =
        new ElisionDecision(
            removed ? Set.of() : Set.of(coordinate),
            removed ? Set.of(coordinate) : Set.of(),
            Map.of(),
            Map.of(),
            0L);
    return new ElisionAnalysisModel.Analysis(
        new ElisionAnalysisModel.ArtifactViews(
            snapshots(coordinate, originalJar, duplicateExactSnapshots), true, List.of()),
        decision,
        decision,
        new ElisionAnalysisModel.AnalysisEvidence(
            new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
        new TrimResult(trimRecords, List.of(), List.of(), List.of(), 0, 0L, 0, null),
        null,
        null);
  }

  private static List<ElisionAnalysisModel.ArtifactSnapshot> snapshots(
      final ArtifactCoordinate coordinate,
      final Path originalJar,
      final boolean duplicateExactSnapshots) {
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(null, coordinate, originalJar);
    return duplicateExactSnapshots ? List.of(snapshot, snapshot) : List.of(snapshot);
  }

  private static VulnerabilityMappingConfig pomAssertion() {
    final VulnerabilityMappingConfig config = new VulnerabilityMappingConfig();
    config.setCveId(MavenCorroboratedSourceArchiveFixtures.CVE_ID);
    config.setGroupId(MavenCorroboratedSourceArchiveFixtures.GROUP_ID);
    config.setArtifactId(MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID);
    config.setVersion(MavenCorroboratedSourceArchiveFixtures.VERSION);
    config.setVersionRangeSpec("[1.0,2.0)");
    config.setVulnerableClasses(List.of("org.example.Outer"));
    return config;
  }
}
