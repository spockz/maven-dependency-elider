// WHY: Keeps multi-candidate invocation fixtures out of the single-candidate proof scenarios.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;

/** Builds multi-candidate production assessments for invocation reuse tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenSourceReproductionReuseScenarios {
  private MavenSourceReproductionReuseScenarios() {}

  static MavenVulnerabilityAssessment.Result assessSingle(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final MavenSourceCorrespondenceTestArtifacts.Archives archives,
      final Path trimmedJar,
      final boolean conventionalLayoutAssumed,
      final MavenSourceCorrespondenceAssessment sourceAssessment)
      throws IOException {
    MavenStructuredProofScenario.copyCurrentCveRecord(prepared);
    final ArtifactTrimRecord record =
        trimRecord(prepared.coordinate(), archives.originalJar(), trimmedJar);
    final ElisionAnalysisModel.Analysis analysis =
        MavenCorroboratedSourceAnalysisFixtures.analysis(
            prepared.coordinate(), archives.originalJar(), List.of(record), false, false);
    return new MavenVulnerabilityAssessment(
            new RecordingMavenLog(),
            new VulnerabilityCacheManager(),
            conventionalLayoutAssumed,
            sourceAssessment)
        .assess(prepared.cacheConfig(), ConfiguredVulnerabilityMappings.empty(), analysis, null);
  }

  static MavenSourceCorrespondenceAssessment sourceAssessmentByArtifact(
      final Map<String, Path> sourcesByArtifact, final boolean conventionalLayoutAssumed) {
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
    final MavenSourceClassifierResolver resolver =
        new MavenSourceClassifierResolver(
            MavenMultiSourceResolverFixture.resolver(sourcesByArtifact, remote, ignored -> {}));
    return MavenSourceCorrespondenceAssessment.configured(
        project, session, Optional.of(resolver), conventionalLayoutAssumed);
  }

  static MavenVulnerabilityAssessment.Result assess(
      final MavenCorroboratedSourceScenario.Prepared prepared,
      final ElisionAnalysisModel.Analysis analysis,
      final MavenSourceCorrespondenceAssessment sourceAssessment)
      throws IOException {
    MavenStructuredProofScenario.copyCurrentCveRecord(prepared);
    return new MavenVulnerabilityAssessment(
            new RecordingMavenLog(), new VulnerabilityCacheManager(), true, sourceAssessment)
        .assess(prepared.cacheConfig(), ConfiguredVulnerabilityMappings.empty(), analysis, null);
  }

  static ArtifactTrimRecord trimRecord(
      final ArtifactCoordinate coordinate, final Path originalJar, final Path trimmedJar)
      throws IOException {
    final ArtifactDigests originalDigest = ArtifactDigests.read(originalJar);
    final ArtifactDigests trimmedDigest = ArtifactDigests.read(trimmedJar);
    return new ArtifactTrimRecord(
        coordinate,
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
}
