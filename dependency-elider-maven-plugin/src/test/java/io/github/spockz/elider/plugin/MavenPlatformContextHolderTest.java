/* WHY: Proves immutable runtime module snapshots are shared only within one Maven execution. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"PMD.CommentRequired", "PMD.AtLeastOneConstructor"})
class MavenPlatformContextHolderTest {
  @Test
  @DisplayName("P02: Maven session clones share one request-scoped module context")
  void sessionClonesShareRequestScopedContext() throws Exception {
    final MavenSession session = session(new DefaultMavenExecutionRequest());
    final MavenSession clone = session.clone();
    try (JdkPlatformContext original = MavenPlatformContextHolder.forOperation(session)) {
      assertAll(
          "Maven session clones share the request-scoped platform context",
          () -> assertThat(clone.getRequest()).isSameAs(session.getRequest()),
          () -> assertThat(MavenPlatformContextHolder.forOperation(clone)).isSameAs(original),
          () ->
              assertThat(MavenPlatformContextHolder.forOperation(session).snapshot())
                  .isSameAs(original.snapshot()));
    }
  }

  @Test
  @DisplayName("P02: single-release analysis reuses one request snapshot for every candidate")
  void singleReleaseAnalysisUsesRequestSnapshotForAllCandidates() throws Exception {
    final MavenProject project = new MavenProject();
    final MavenSession session = session(new DefaultMavenExecutionRequest(), project);
    final TrimRequest request =
        new TrimRequest(
            project,
            session,
            new AnalysisEnvironment(
                Map.of(),
                Map.of("maven.compiler.release", Integer.toString(Runtime.version().feature())),
                null,
                AnalysisEnvironment.JdkToolchainState.UNSELECTED,
                null),
            List.of(artifactSnapshot("first-library"), artifactSnapshot("second-library")),
            new TrimScanInputs(null, Map.of()),
            Set.of(),
            new TrimEvidence(null, Set.of(), Set.of(), Set.of()),
            new TrimPolicy(List.of(), false, List.of(), false),
            Optional.empty());
    try (JdkPlatformContext requestContext = MavenPlatformContextHolder.forOperation(session)) {
      final JdkPlatformContext.PlatformSnapshot requestSnapshot = requestContext.snapshot();
      final SingleReleasePlatforms.AnalysisPlatform analysis =
          SingleReleasePlatforms.prepare(request);

      assertAll(
          "one active-runtime snapshot backs the complete candidate analysis",
          () -> assertThat(request.candidates()).hasSize(2),
          () -> assertThat(analysis.snapshots()).hasSize(1),
          () -> assertThat(analysis.snapshots().getFirst()).isSameAs(requestSnapshot));
    }
  }

  @Test
  @DisplayName("P02: standalone calls receive fresh operation contexts")
  void standaloneCallsDoNotShareContexts() throws Exception {
    try (JdkPlatformContext first = MavenPlatformContextHolder.forOperation(null);
        JdkPlatformContext second = MavenPlatformContextHolder.forOperation(null)) {
      assertThat(first).isNotSameAs(second);
    }
  }

  @Test
  @DisplayName("P02: independent Maven requests own isolated module contexts")
  void independentRequestsUseIsolatedContexts() throws Exception {
    final MavenSession firstSession = session(new DefaultMavenExecutionRequest());
    final MavenSession secondSession = session(new DefaultMavenExecutionRequest());
    try (JdkPlatformContext first = MavenPlatformContextHolder.forOperation(firstSession);
        JdkPlatformContext second = MavenPlatformContextHolder.forOperation(secondSession)) {
      assertAll(
          "separate Maven executions do not share runtime snapshots",
          () -> assertThat(second).isNotSameAs(first));
    }
  }

  private MavenSession session(final MavenExecutionRequest request, final MavenProject project) {
    return new MavenSession(null, request, null, project);
  }

  private MavenSession session(final MavenExecutionRequest request) {
    return session(request, new MavenProject());
  }

  private static ElisionAnalysisModel.ArtifactSnapshot artifactSnapshot(final String artifactId) {
    return new ElisionAnalysisModel.ArtifactSnapshot(
        null, ArtifactCoordinate.of("fixture", artifactId, "1"), Path.of(artifactId + ".jar"));
  }
}
