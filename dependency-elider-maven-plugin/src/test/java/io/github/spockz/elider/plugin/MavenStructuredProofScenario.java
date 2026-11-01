// WHY: Builds production assessment inputs for live structured omitted-code proof tests.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;

/** Builds one live structured proof assessment. */
final class MavenStructuredProofScenario {
  private MavenStructuredProofScenario() {}

  /* default */ static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    return assess(prepared, archives, trimmedJar, conventionalLayoutAssumed, ignored -> {});
  }

  /* default */ static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed,
      final Consumer<RepositorySystemSession> resolutionObserver)
      throws IOException {
    return assess(
        prepared,
        archives,
        trimmedJar,
        conventionalLayoutAssumed,
        ConfiguredVulnerabilityMappings.empty(),
        resolutionObserver);
  }

  /* default */ static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed,
      final ConfiguredVulnerabilityMappings configured,
      final Consumer<RepositorySystemSession> resolutionObserver)
      throws IOException {
    return assessWithLog(
            prepared,
            archives,
            trimmedJar,
            conventionalLayoutAssumed,
            configured,
            resolutionObserver,
            false)
        .result();
  }

  /* default */ static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final ElisionAnalysisModel.Analysis analysis,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    copyCurrentCveRecord(prepared);
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        sourceAssessment(archives, conventionalLayoutAssumed, ignored -> {});
    return new MavenVulnerabilityAssessment(
            new RecordingMavenLog(),
            new VulnerabilityCacheManager(),
            conventionalLayoutAssumed,
            sourceAssessment)
        .assess(prepared.cacheConfig(), ConfiguredVulnerabilityMappings.empty(), analysis, null);
  }

  /* default */ static MavenCorroboratedSourceScenario.AssessmentWithLog assessWithDebugLog(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed,
      final Consumer<RepositorySystemSession> resolutionObserver)
      throws IOException {
    return assessWithLog(
        prepared,
        archives,
        trimmedJar,
        conventionalLayoutAssumed,
        ConfiguredVulnerabilityMappings.empty(),
        resolutionObserver,
        true);
  }

  private static MavenCorroboratedSourceScenario.AssessmentWithLog assessWithLog(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed,
      final ConfiguredVulnerabilityMappings configured,
      final Consumer<RepositorySystemSession> resolutionObserver,
      final boolean debugEnabled)
      throws IOException {
    copyCurrentCveRecord(prepared);
    final ArtifactTrimRecord trimRecord = trimRecord(prepared, archives.originalJar(), trimmedJar);
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        sourceAssessment(archives, conventionalLayoutAssumed, resolutionObserver);
    final RecordingMavenLog log = new RecordingMavenLog(debugEnabled);
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(
                log, new VulnerabilityCacheManager(), conventionalLayoutAssumed, sourceAssessment)
            .assess(
                prepared.cacheConfig(),
                configured,
                MavenCorroboratedSourceAnalysisFixtures.analysis(
                    prepared.coordinate(),
                    archives.originalJar(),
                    List.of(trimRecord),
                    false,
                    false),
                null);
    return new MavenCorroboratedSourceScenario.AssessmentWithLog(result, log);
  }

  private static void copyCurrentCveRecord(final MavenCorroboratedSourceScenario.Prepared prepared)
      throws IOException {
    final Path currentCveRecord =
        prepared
            .cacheConfig()
            .cacheDirectory()
            .resolve("cvelistV5/cves/2025/12xxx/CVE-2025-12345.json");
    Files.createDirectories(currentCveRecord.getParent());
    Files.copy(
        prepared.cveRecord(), currentCveRecord, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
  }

  /* default */ static ArtifactTrimRecord trimRecord(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final Path originalJar,
      final Path trimmedJar)
      throws IOException {
    final ArtifactDigests originalDigest = ArtifactDigests.read(originalJar);
    final ArtifactDigests trimmedDigest = ArtifactDigests.read(trimmedJar);
    return new ArtifactTrimRecord(
        prepared.coordinate(),
        originalJar,
        originalDigest.sha256(),
        originalDigest.sha1(),
        trimmedJar,
        trimmedDigest.sha256(),
        trimmedDigest.sha1(),
        5,
        0,
        256);
  }

  private static MavenSourceCorrespondenceAssessment sourceAssessment(
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final boolean conventionalLayoutAssumed,
      final Consumer<RepositorySystemSession> resolutionObserver) {
    final MavenProject project = new MavenProject();
    project.setRemoteArtifactRepositories(List.of());
    final MavenSession session =
        new MavenSession(
            null,
            new org.eclipse.aether.DefaultRepositorySystemSession(),
            new DefaultMavenExecutionRequest(),
            null);
    final ArtifactRepository remote =
        new RemoteRepository.Builder(
                "fixture-remote", "default", "https://repo.example.invalid/maven2")
            .build();
    final RepositorySystem resolverSystem =
        MavenSourceCorrespondenceTestArtifacts.resolver(
            archives.sourcesJar(), remote, resolutionObserver);
    final MavenSourceClassifierResolver resolver =
        new MavenSourceClassifierResolver(resolverSystem);
    return MavenSourceCorrespondenceAssessment.configured(
        project, session, Optional.of(resolver), conventionalLayoutAssumed);
  }
}
