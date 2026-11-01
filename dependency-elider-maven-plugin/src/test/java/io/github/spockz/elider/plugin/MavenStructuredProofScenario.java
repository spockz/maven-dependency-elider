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
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Builds one live structured proof assessment. */
final class MavenStructuredProofScenario {
  private MavenStructuredProofScenario() {}

  /* default */ static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    copyCurrentCveRecord(prepared);
    final ArtifactTrimRecord trimRecord = trimRecord(prepared, archives.originalJar(), trimmedJar);
    final MavenSourceCorrespondenceAssessment sourceAssessment =
        sourceAssessment(archives, conventionalLayoutAssumed);
    return new MavenVulnerabilityAssessment(
            new RecordingMavenLog(),
            new VulnerabilityCacheManager(),
            conventionalLayoutAssumed,
            sourceAssessment)
        .assess(
            prepared.cacheConfig(),
            ConfiguredVulnerabilityMappings.empty(),
            MavenCorroboratedSourceAnalysisFixtures.analysis(
                prepared.coordinate(), archives.originalJar(), List.of(trimRecord), false, false),
            null);
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

  private static ArtifactTrimRecord trimRecord(
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
      final boolean conventionalLayoutAssumed) {
    final MavenProject project = new MavenProject();
    project.setRemoteArtifactRepositories(List.of());
    final MavenSession session =
        new MavenSession(
            null,
            new org.eclipse.aether.DefaultRepositorySystemSession(),
            new DefaultMavenExecutionRequest(),
            null);
    final MavenSourceClassifierResolver resolver =
        new MavenSourceClassifierResolver(
            MavenSourceCorrespondenceTestArtifacts.resolver(archives.sourcesJar()));
    return MavenSourceCorrespondenceAssessment.configured(
        project, session, Optional.of(resolver), conventionalLayoutAssumed);
  }
}
