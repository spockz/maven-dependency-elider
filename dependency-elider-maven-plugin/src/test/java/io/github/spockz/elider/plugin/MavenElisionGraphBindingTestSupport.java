/* WHY: Shares Maven session and graph-pair construction across binding tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.graph.DefaultDependencyNode;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.io.TempDir;

/** Provides local Maven inventory and resolver-pair fixtures. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
class MavenElisionGraphBindingTestSupport {

  /** Maven coordinate used by the one-JAR graph fixture. */
  private static final String GROUP_ID = "fixture";

  /** Artifact ID used by the one-JAR graph fixture. */
  private static final String ARTIFACT_ID = "library";

  /** Stable artifact version shared by fixture coordinates. */
  protected static final String VERSION = "1.0";

  /** Compile scope used by Maven and resolver fixture records. */
  private static final String SCOPE = "compile";

  /** Resolver extension represented by the fixture JAR. */
  private static final String JAR_TYPE = "jar";

  /** First deterministic request token used in capture-pair tests. */
  private static final String FIRST_CAPTURE = "capture-1";

  /** Isolated file area for the generated POM and artifact. */
  @TempDir protected Path temporaryDirectory;

  /** JUnit fills the temporary directory field after constructing this fixture base. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  MavenElisionGraphBindingTestSupport() {}

  /** Creates a graph and matching resolved artifact, optionally with TEST context. */
  protected Fixture fixture(final boolean testContext, final String content) throws IOException {
    final MavenProject project = new MavenProject();
    project.setFile(Files.createFile(temporaryDirectory.resolve("pom.xml")).toFile());
    project.setGroupId("fixture");
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Artifact artifact = artifact("library.jar", VERSION);
    Files.writeString(artifactPath(artifact), content);
    final MavenElisionService.ArtifactSnapshot snapshot =
        new MavenElisionService.ArtifactSnapshot(
            artifact, coordinate(VERSION), artifactPath(artifact));
    final DefaultRepositorySystemSession repositorySession = new DefaultRepositorySystemSession();
    final MavenSession session =
        new MavenSession(
            null,
            repositorySession,
            new org.apache.maven.execution.DefaultMavenExecutionRequest(),
            null);
    final String projectKey = projectKey(project);
    appendPair(repositorySession, projectKey, FIRST_CAPTURE);
    final MavenElisionService.AnalysisOptions options =
        new MavenElisionService.AnalysisOptions(
            List.of(),
            List.of(),
            null,
            session,
            false,
            false,
            List.of(),
            false,
            List.of(),
            false,
            testContext);
    return new Fixture(project, options, repositorySession, snapshot);
  }

  /** Adds a deterministic capture pair to the test session's JDK-only store. */
  static void appendPair(
      final DefaultRepositorySystemSession session, final String projectKey, final String token) {
    appendPair(session, projectKey, token, SCOPE);
  }

  /** Adds a capture pair with a selected effective graph scope. */
  @SuppressWarnings("PMD.LawOfDemeter")
  static void appendPair(
      final DefaultRepositorySystemSession session,
      final String projectKey,
      final String token,
      final String graphScope) {
    final long generation = FIRST_CAPTURE.equals(token) ? 1L : 2L;
    final DependencyNode before = graph(graphScope);
    final DependencyNode after = graph(graphScope);
    final ResolverArtifactGraphCapturePair pair =
        new ResolverArtifactGraphCapturePair(
            projectKey,
            token,
            generation,
            false,
            null,
            0L,
            ResolverArtifactGraphSnapshot.capture(before, projectKey, false, null, 0L, generation),
            ResolverArtifactGraphSnapshot.capture(after, projectKey, false, null, 0L, generation));
    final Object existing =
        session.getData().get(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
    final ResolverArtifactGraphSnapshotStore store =
        ResolverArtifactGraphSnapshotStore.fromPayload(existing);
    session
        .getData()
        .set(
            EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY,
            existing,
            store.append(pair).toPayload());
  }

  private static DependencyNode graph(final String scope) {
    final DependencyNode root =
        new DefaultDependencyNode(
            new Dependency(
                new org.eclipse.aether.artifact.DefaultArtifact(
                    GROUP_ID, "consumer", "", "pom", VERSION),
                "",
                false));
    final DependencyNode library =
        new DefaultDependencyNode(
            new Dependency(
                new org.eclipse.aether.artifact.DefaultArtifact(
                    GROUP_ID, ARTIFACT_ID, "", "jar", VERSION),
                scope,
                false));
    root.setChildren(List.of(library));
    library.setChildren(List.of());
    return root;
  }

  /** Computes the stable identity key used by the resolver snapshot store. */
  @SuppressWarnings("PMD.LawOfDemeter")
  protected static String projectKey(final MavenProject project) {
    return ResolverArtifactPlanStore.projectKey(
        new ResolverArtifactPlan.ProjectIdentity(
            project.getBasedir().toPath(),
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion()));
  }

  /** Writes the fixture bytes and creates the corresponding Maven artifact. */
  protected Artifact artifact(final String fileName, final String version) throws IOException {
    final Path file = Files.createFile(temporaryDirectory.resolve(fileName));
    final Artifact artifact =
        new DefaultArtifact(
            GROUP_ID,
            ARTIFACT_ID,
            version,
            SCOPE,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    artifact.setFile(file.toFile());
    return artifact;
  }

  /** Creates the resolver coordinate matching this fixture's Maven artifact. */
  protected static ArtifactCoordinate coordinate(final String version) {
    return new ArtifactCoordinate(GROUP_ID, ARTIFACT_ID, version, JAR_TYPE, "", SCOPE);
  }

  /** Normalizes the backing file path supplied by Maven's artifact view. */
  protected static Path artifactPath(final Artifact artifact) {
    return Objects.requireNonNull(artifact.getFile()).toPath().toAbsolutePath().normalize();
  }

  record Fixture(
      MavenProject project,
      MavenElisionService.AnalysisOptions options,
      DefaultRepositorySystemSession repositorySession,
      MavenElisionService.ArtifactSnapshot snapshot) {
    /** Binds this fixture pair to the supplied resolved inventory. */
    MavenElisionGraphBinding.Result bind(final List<MavenElisionService.ArtifactSnapshot> inventory)
        throws IOException {
      return bind(
          inventory,
          new ElisionDecision(Set.of(coordinate(VERSION)), Set.of(), Map.of(), Map.of(), 0L));
    }

    /** Binds this fixture pair to a supplied raw decision and resolved inventory. */
    MavenElisionGraphBinding.Result bind(
        final List<MavenElisionService.ArtifactSnapshot> inventory, final ElisionDecision decision)
        throws IOException {
      return bind(options, inventory, decision);
    }

    MavenElisionGraphBinding.Result bind(
        final MavenElisionService.AnalysisOptions selectedOptions,
        final List<MavenElisionService.ArtifactSnapshot> inventory,
        final ElisionDecision decision)
        throws IOException {
      return MavenElisionGraphBinding.bind(
          project,
          selectedOptions,
          inventory,
          decision,
          TraceData.of(Set.of("fixture.Keep")),
          Set.of("fixture.Keep"));
    }

    Object sessionValue(final String key) {
      return repositorySession.getData().get(key);
    }

    void clearCapturePairs() {
      final Object existing = sessionValue(EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY);
      repositorySession
          .getData()
          .set(
              EliderMediatedGraphCaptureDecorator.SESSION_DATA_KEY,
              existing,
              ResolverArtifactGraphSnapshotStore.empty().toPayload());
    }

    void replaceGraphScope(final String graphScope) {
      clearCapturePairs();
      appendPair(repositorySession, projectKey(project), FIRST_CAPTURE, graphScope);
    }
  }
}
