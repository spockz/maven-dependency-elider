// WHY: Proves the compiler handoff contains only mediated, policy-allowed original files.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks the policy boundary of the original test compilation view. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.CommentRequired",
  "PMD.LawOfDemeter"
})
final class EliderTestViewPlanTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void publishesOnlyAllowedMediatedArtifactsInTheirOriginalOrder() throws Exception {
    final MavenProject project = project();
    final Artifact selected = artifact("library", "2", "compile", null);
    final Artifact banned = artifact("banned", "1", "compile", null);
    final Artifact provided = artifact("provided-library", "1", "provided", null);
    final Artifact runtime = artifact("runtime-library", "1", "runtime", null);
    final Artifact test = artifact("test-library", "1", "test", null);
    final Artifact classified = artifact("library", "2", "test", "fixtures");
    final Path unselectedVersion = Files.createFile(temporaryDirectory.resolve("library-1.jar"));
    final Path excludedOriginal = Files.createFile(temporaryDirectory.resolve("excluded-1.jar"));
    project.setArtifacts(
        new LinkedHashSet<>(List.of(selected, banned, provided, runtime, test, classified)));
    final MavenSession session = session(project);

    final EliderTestViewPlan.Prepared prepared =
        EliderTestViewPlan.prepare(
            session,
            project,
            Set.of(new ArtifactCoordinate("fixture", "banned", "1", "jar", "", "compile")),
            temporaryDirectory.resolve("production-report.json"));
    EliderTestViewPlan.publish(session, prepared);
    final EliderTestViewPlan.Plan plan = EliderTestViewPlan.read(session, project);

    assertAll(
        "allowed mediated originals",
        () ->
            assertThat(plan.artifacts())
                .extracting(descriptor -> descriptor.identity().artifactId())
                .containsExactly(
                    "library", "provided-library", "runtime-library", "test-library", "library"),
        () ->
            assertThat(plan.artifacts())
                .extracting(descriptor -> descriptor.identity().scope())
                .containsExactly("compile", "provided", "runtime", "test", "test"),
        () ->
            assertThat(plan.artifacts())
                .extracting(descriptor -> descriptor.identity().classifier())
                .containsExactly("", "", "", "", "fixtures"),
        () -> assertThat(plan.artifacts().getFirst().identity().version()).isEqualTo("2"),
        () ->
            assertThat(plan.productionReport())
                .isEqualTo(temporaryDirectory.resolve("production-report.json").toString()),
        () ->
            assertThat(plan.artifacts())
                .extracting(EliderTestViewPlan.Descriptor::path)
                .containsExactly(
                    path(selected), path(provided), path(runtime), path(test), path(classified)),
        () ->
            assertThat(plan.artifacts())
                .extracting(EliderTestViewPlan.Descriptor::path)
                .doesNotContain(
                    path(banned), unselectedVersion.toString(), excludedOriginal.toString()),
        () -> assertThat(banned.getFile().toPath()).exists());
  }

  @Test
  void rejectsBanPlanWithDifferentScopeForSameArtifactIdentity() throws Exception {
    final MavenProject project = project();
    project.setArtifacts(new LinkedHashSet<>(List.of(artifact("banned", "1", "test", null))));
    final MavenSession session = session(project);

    assertThatThrownBy(
            () ->
                EliderTestViewPlan.prepare(
                    session,
                    project,
                    Set.of(new ArtifactCoordinate("fixture", "banned", "1", "jar", "", "compile")),
                    temporaryDirectory.resolve("production-report.json")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("scope mismatch");
  }

  @Test
  void acceptsOneOptedInReactorLeafAndRejectsTwo() throws Exception {
    final MavenProject upstream = new MavenProject();
    upstream.setGroupId("fixture");
    upstream.setArtifactId("upstream");
    upstream.setVersion("1");
    upstream.setFile(Files.createFile(temporaryDirectory.resolve("upstream-pom.xml")).toFile());
    final MavenProject leaf = project();
    final MavenSession session = session(leaf);
    session.setProjects(List.of(upstream, leaf));
    final Path report = temporaryDirectory.resolve("production-report.json");

    assertAll(
        "a reactor may have one isolated test-view consumer",
        () -> assertThat(EliderTestViewPlan.prepare(session, leaf, Set.of(), report)).isNotNull(),
        () -> {
          upstream.getProperties().setProperty(EliderTestViewPlan.ENABLE_PROPERTY, "true");
          assertThatThrownBy(() -> EliderTestViewPlan.prepare(session, leaf, Set.of(), report))
              .isInstanceOf(IOException.class)
              .hasMessageContaining("exactly one opted-in Maven project");
        });
  }

  @Test
  void rejectsParallelReactorBeforePublishingTheCompilerView() throws Exception {
    final MavenProject project = project();
    final MavenSession session = session(project);
    session.getRequest().setDegreeOfConcurrency(2);

    assertThatThrownBy(
            () ->
                EliderTestViewPlan.prepare(
                    session,
                    project,
                    Set.of(),
                    temporaryDirectory.resolve("production-report.json")))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("parallel Maven reactor");
  }

  private MavenProject project() throws IOException {
    final MavenProject project = new MavenProject();
    project.setGroupId("fixture");
    project.setArtifactId("consumer");
    project.setVersion("1");
    project.setFile(Files.createFile(temporaryDirectory.resolve("pom.xml")).toFile());
    project.getProperties().setProperty(EliderTestViewPlan.ENABLE_PROPERTY, "true");
    return project;
  }

  private MavenSession session(final MavenProject project) {
    final MavenSession session =
        new MavenSession(
            null, new DefaultRepositorySystemSession(), new DefaultMavenExecutionRequest(), null);
    session.setProjects(List.of(project));
    MavenOriginalInputAudit.markHookPresent(session);
    return session;
  }

  private Artifact artifact(
      final String name, final String version, final String scope, final String classifier)
      throws IOException {
    final DefaultArtifact artifact =
        new DefaultArtifact(
            "fixture", name, version, scope, "jar", classifier, new DefaultArtifactHandler("jar"));
    artifact.setFile(
        Files.createFile(
                temporaryDirectory.resolve(
                    name
                        + "-"
                        + version
                        + "-"
                        + scope
                        + (classifier == null ? "" : "-" + classifier)
                        + ".jar"))
            .toFile());
    return artifact;
  }

  private static String path(final Artifact artifact) {
    return artifact.getFile().toPath().toAbsolutePath().normalize().toString();
  }
}
