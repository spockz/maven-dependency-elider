/* WHY: Seeds the same captured Resolver graph for Analyze and Elide goal fixtures. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.nio.file.Path;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.DefaultMavenExecutionResult;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.apache.maven.toolchain.DefaultToolchainManager;
import org.codehaus.plexus.PlexusContainer;
import org.eclipse.aether.DefaultRepositorySystemSession;

/** Shares Maven session and captured graph setup across goal parity tests. */
final class RuntimeEvidenceGoalFixture {
  /** Maven project injection field name. */
  /* default */ static final String PROJECT_FIELD = "project";

  /** Maven session injection field name. */
  /* default */ static final String SESSION_FIELD = "session";

  /** Runtime evidence parameter field name. */
  /* default */ static final String TRACE_FILES_FIELD = "traceFiles";

  /** Closed-world parameter field name. */
  /* default */ static final String CLOSED_WORLD_FIELD = "closedWorld";

  private RuntimeEvidenceGoalFixture() {}

  /** Maven exposes its active archive path through the Artifact file pointer. */
  @SuppressWarnings("PMD.LawOfDemeter")
  /* default */ static Path artifactPath(final Artifact artifact) {
    return artifact.getFile().toPath();
  }

  /** URLClassLoader needs a file URL for each applied artifact archive. */
  /* default */ static URL archiveUrl(final Path path) throws IOException {
    return path.toUri().toURL();
  }

  /* default */ static MavenSession session(final MavenProject project) {
    final PlexusContainer container =
        (PlexusContainer)
            Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[] {PlexusContainer.class},
                (proxy, method, arguments) ->
                    "lookup".equals(method.getName()) ? new DefaultToolchainManager() : null);
    final MavenSession session =
        new MavenSession(
            container,
            new DefaultRepositorySystemSession(),
            new DefaultMavenExecutionRequest(),
            new DefaultMavenExecutionResult());
    session.setCurrentProject(project);
    return session;
  }

  /* default */ static void seedCapturedGraph(
      final MavenSession session,
      final MavenDependencyTrimmerInMemoryClosureSupport.Fixture fixture) {
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.empty().append(pair);
    EliderPreparationState.sessionData(session)
        .set(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY, null, store.toPayload());
    MavenOriginalInputAudit.markHookPresent(session);
  }
}
