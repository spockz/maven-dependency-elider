/* WHY: Tests reactor leaf module detection so intermediate modules are identified
 * and skipped when elide.leafOnly is active (ADR-0011). */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.execution.ProjectDependencyGraph;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests leaf module detection for reactor builds. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AtLeastOneConstructor"
})
final class ReactorLeafModuleDetectorTest {
  private static final String PACKAGING_JAR = "jar";
  private static final String PACKAGING_POM = "pom";

  @Test
  @DisplayName("ADR-0011: null project or session is never treated as intermediate")
  void nullProjectOrSessionReturnsFalse() {
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(null, null)).isFalse();
    final MavenProject project = createProject("standalone", PACKAGING_JAR);
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(project, null)).isFalse();
    final MavenSession session = createSession(null);
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(null, session)).isFalse();
  }

  @Test
  @DisplayName("ADR-0011: session with no graph is treated as standalone leaf")
  void sessionWithNoGraphReturnsFalse() {
    final MavenProject project = createProject("standalone", PACKAGING_JAR);
    final MavenSession session = createSession(null);
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(project, session)).isFalse();
  }

  @Test
  @DisplayName("ADR-0011: single-project build with graph is treated as leaf")
  void singleProjectGraphReturnsFalse() {
    final MavenProject project = createProject("standalone", PACKAGING_JAR);
    final ProjectDependencyGraph graph =
        new StubProjectDependencyGraph(List.of(project), Map.of(project, List.of()));
    final MavenSession session = createSession(graph);
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(project, session)).isFalse();
  }

  @Test
  @DisplayName("ADR-0011: multi-module reactor POM packaging is treated as intermediate")
  void multiModulePomPackagingIsIntermediate() {
    final MavenProject rootPom = createProject("root", PACKAGING_POM);
    final MavenProject childApp = createProject("app", PACKAGING_JAR);
    final ProjectDependencyGraph graph =
        new StubProjectDependencyGraph(
            List.of(rootPom, childApp),
            Map.of(
                rootPom, List.of(childApp),
                childApp, List.of()));
    final MavenSession session = createSession(graph);
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(rootPom, session)).isTrue();
  }

  @Test
  @DisplayName("ADR-0011: module with downstream reactor dependents is treated as intermediate")
  void moduleWithDownstreamDependentsIsIntermediate() {
    final MavenProject common = createProject("common", PACKAGING_JAR);
    final MavenProject service = createProject("service", PACKAGING_JAR);
    final MavenProject app = createProject("app", PACKAGING_JAR);
    final ProjectDependencyGraph graph =
        new StubProjectDependencyGraph(
            List.of(common, service, app),
            Map.of(
                common, List.of(service, app),
                service, List.of(app),
                app, List.of()));
    final MavenSession session = createSession(graph);

    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(common, session)).isTrue();
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(service, session)).isTrue();
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(app, session)).isFalse();
  }

  @Test
  @DisplayName("ADR-0011: multiple leaf modules in the same reactor are all identified as leaves")
  void multipleLeafModulesAreIdentifiedAsLeaves() {
    final MavenProject core = createProject("core", PACKAGING_JAR);
    final MavenProject webApp = createProject("web-app", PACKAGING_JAR);
    final MavenProject cliApp = createProject("cli-app", PACKAGING_JAR);
    final ProjectDependencyGraph graph =
        new StubProjectDependencyGraph(
            List.of(core, webApp, cliApp),
            Map.of(
                core, List.of(webApp, cliApp),
                webApp, List.of(),
                cliApp, List.of()));
    final MavenSession session = createSession(graph);

    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(core, session)).isTrue();
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(webApp, session)).isFalse();
    assertThat(ReactorLeafModuleDetector.isIntermediateReactorModule(cliApp, session)).isFalse();
  }

  private static MavenProject createProject(final String artifactId, final String packaging) {
    final MavenProject project = new MavenProject();
    project.setGroupId("io.github.spockz.test");
    project.setArtifactId(artifactId);
    project.setVersion("1.0.0");
    project.setPackaging(packaging);
    return project;
  }

  private static MavenSession createSession(final ProjectDependencyGraph graph) {
    final MavenExecutionRequest request = new DefaultMavenExecutionRequest();
    final DefaultRepositorySystemSession repoSession = MavenRepositorySystemUtils.newSession();
    final MavenSession session = new MavenSession(null, repoSession, request, null);
    session.setProjectDependencyGraph(graph);
    return session;
  }

  @SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
  private static final class StubProjectDependencyGraph implements ProjectDependencyGraph {
    private final List<MavenProject> allProjects;
    private final Map<MavenProject, List<MavenProject>> downstream;

    StubProjectDependencyGraph(
        final List<MavenProject> allProjects,
        final Map<MavenProject, List<MavenProject>> downstream) {
      this.allProjects = allProjects;
      this.downstream = downstream;
    }

    @Override
    public List<MavenProject> getAllProjects() {
      return allProjects;
    }

    @Override
    public List<MavenProject> getSortedProjects() {
      return allProjects;
    }

    @Override
    public List<MavenProject> getDownstreamProjects(
        final MavenProject project, final boolean transitive) {
      return downstream.getOrDefault(project, List.of());
    }

    @Override
    public List<MavenProject> getUpstreamProjects(
        final MavenProject project, final boolean transitive) {
      return List.of();
    }
  }
}
