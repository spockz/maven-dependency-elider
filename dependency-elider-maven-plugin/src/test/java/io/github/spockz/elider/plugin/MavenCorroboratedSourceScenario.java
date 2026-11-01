// WHY: Assembles one cache-to-assessment path for source-corroboration behavior tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.scanner.OsvSnapshotIndexer;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/** Shares setup between the proof-positive and review-only assertions. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
final class MavenCorroboratedSourceScenario {
  record Prepared(
      VulnerabilityCacheManager.CacheConfig cacheConfig,
      ArtifactCoordinate coordinate,
      Path originalJar,
      Path cveRecord,
      String cveDigest,
      ArtifactDigests originalDigest,
      ArtifactTrimRecord successfulTrimRecord,
      MavenVulnerabilityAssessment.Result result) {}

  record AssessmentWithLog(MavenVulnerabilityAssessment.Result result, RecordingMavenLog log) {}

  private MavenCorroboratedSourceScenario() {}

  static Prepared prepare(final Path directory) throws IOException {
    return prepareFromCveRecord(
        directory,
        MavenCorroboratedSourceArchiveFixtures.writeCveRecord(directory),
        true,
        MavenCorroboratedSourceArchiveFixtures.VERSION);
  }

  static Prepared prepareSourceClaim(
      final Path directory,
      final boolean routineOnly,
      final String defaultStatus,
      final String version)
      throws IOException {
    final Path cveRecord =
        routineOnly
            ? MavenCorroboratedSourceArchiveFixtures.writeRoutineOnlyRecord(
                directory, defaultStatus)
            : MavenCorroboratedSourceArchiveFixtures.writeUnmatchedFileOnlyRecord(directory);
    return prepareFromCveRecord(directory, cveRecord, false, version);
  }

  static Prepared prepareAmbiguousProductClaim(final Path directory, final boolean reverse)
      throws IOException {
    return prepareFromCveRecord(
        directory,
        MavenAmbiguousCnaProductFixture.write(directory, reverse),
        false,
        MavenCorroboratedSourceArchiveFixtures.VERSION);
  }

  static Prepared prepareReproducibleClaim(
      final Path directory, final List<String> programFiles, final List<String> routineNames)
      throws IOException {
    return prepareFromCveRecord(
        directory,
        MavenCorroboratedSourceArchiveFixtures.writeCorrespondenceRecord(
            directory, programFiles, routineNames),
        false,
        MavenCorroboratedSourceArchiveFixtures.VERSION);
  }

  static MavenVulnerabilityAssessment.Result assessWithSourceClassifier(
      final Prepared prepared,
      final Path originalJar,
      final MavenSourceClassifierResolver resolver,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    final org.apache.maven.project.MavenProject project =
        new org.apache.maven.project.MavenProject();
    project.setRemoteArtifactRepositories(List.of());
    final org.apache.maven.execution.MavenSession session =
        new org.apache.maven.execution.MavenSession(
            null,
            new org.eclipse.aether.DefaultRepositorySystemSession(),
            new org.apache.maven.execution.DefaultMavenExecutionRequest(),
            null);
    return new MavenVulnerabilityAssessment(
            new RecordingMavenLog(),
            new VulnerabilityCacheManager(),
            conventionalLayoutAssumed,
            MavenSourceCorrespondenceAssessment.configured(
                project, session, java.util.Optional.of(resolver), conventionalLayoutAssumed))
        .assess(
            prepared.cacheConfig(),
            ConfiguredVulnerabilityMappings.empty(),
            MavenCorroboratedSourceAnalysisFixtures.analysis(
                prepared.coordinate(), originalJar, List.of(), false, false),
            null);
  }

  private static Prepared prepareFromCveRecord(
      final Path directory,
      final Path cveRecord,
      final boolean ownerAssertion,
      final String version)
      throws IOException {
    final String cveDigest = ArtifactDigests.read(cveRecord).sha256();
    final List<OsvAdvisoryRecord> indexedRecords =
        new OsvSnapshotIndexer()
            .indexZip(
                new ByteArrayInputStream(MavenCorroboratedSourceArchiveFixtures.osvSnapshot()),
                directory);
    final List<OsvAdvisoryRecord> records =
        ownerAssertion
            ? List.of(
                MavenCorroboratedSourceCacheFixtures.withStaleCorroboratedCandidate(
                    indexedRecords.getFirst()))
            : indexedRecords;
    final Path cacheDirectory = Files.createDirectories(directory.resolve("cache"));
    MavenAssessmentFixtures.writeCacheRecords(cacheDirectory, records);
    final Path originalJar =
        MavenCorroboratedSourceArchiveFixtures.writeOriginalJar(
            directory.resolve("original.jar"), false);
    final Path trimmedJar = directory.resolve("trimmed.jar");
    MavenCorroboratedSourceArchiveFixtures.writeTrimmedJar(trimmedJar);
    final ArtifactCoordinate coordinate =
        ArtifactCoordinate.of(
            MavenCorroboratedSourceArchiveFixtures.GROUP_ID,
            MavenCorroboratedSourceArchiveFixtures.ARTIFACT_ID,
            version);
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
                ownerAssertion
                    ? ConfiguredVulnerabilityMappings.fromPom(List.of(pomAssertion()))
                    : ConfiguredVulnerabilityMappings.empty(),
                MavenCorroboratedSourceAnalysisFixtures.analysis(
                    coordinate, originalJar, List.of(trimRecord), false, false),
                null);
    return new Prepared(
        cacheConfig,
        coordinate,
        originalJar,
        cveRecord,
        cveDigest,
        originalDigest,
        trimRecord,
        result);
  }

  static MavenVulnerabilityAssessment.Result assessWithLayoutFlag(
      final Prepared prepared, final boolean assumed, final boolean ownerAssertion)
      throws IOException {
    return new MavenVulnerabilityAssessment(new RecordingMavenLog(), assumed)
        .assess(
            prepared.cacheConfig(),
            ownerAssertion
                ? ConfiguredVulnerabilityMappings.fromPom(List.of(pomAssertion()))
                : ConfiguredVulnerabilityMappings.empty(),
            MavenCorroboratedSourceAnalysisFixtures.analysis(
                prepared.coordinate(),
                prepared.originalJar(),
                List.of(prepared.successfulTrimRecord()),
                false,
                false),
            null);
  }

  static MavenVulnerabilityAssessment.Result reassess(
      final Prepared prepared, final boolean removed, final boolean duplicateExactSnapshots)
      throws IOException {
    return new MavenVulnerabilityAssessment(new RecordingMavenLog())
        .assess(
            prepared.cacheConfig(),
            ConfiguredVulnerabilityMappings.empty(),
            MavenCorroboratedSourceAnalysisFixtures.analysis(
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
            MavenCorroboratedSourceAnalysisFixtures.analysis(
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
                MavenCorroboratedSourceAnalysisFixtures.analysis(
                    prepared.coordinate(), originalJar, List.of(), false, false),
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
