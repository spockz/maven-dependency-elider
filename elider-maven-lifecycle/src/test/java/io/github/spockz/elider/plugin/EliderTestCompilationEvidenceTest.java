// WHY: Proves test-view handoffs only trust compiler and preparation evidence from the current
// Maven session and project.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.descriptor.MojoDescriptor;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.project.MavenProject;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks that an isolated test view cannot reuse another project's phase evidence. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.CommentRequired", "PMD.LawOfDemeter"})
final class EliderTestCompilationEvidenceTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void requiresMatchingSuccessfulCompilerCallbackAndCapturesItsConfiguration() throws Exception {
    final MavenSession session = session();
    final MavenProject selected = project("selected");
    final MavenProject other = project("other");
    final PluginDescriptor plugin = new PluginDescriptor();
    plugin.setVersion("3.13.0");
    final MojoDescriptor descriptor = new MojoDescriptor();
    descriptor.setPluginDescriptor(plugin);
    final MojoExecution execution =
        new MojoExecution(descriptor, "default-testCompile", MojoExecution.Source.LIFECYCLE);
    final Xpp3Dom configuration = new Xpp3Dom("configuration");
    final Xpp3Dom release = new Xpp3Dom("release");
    release.setValue("21");
    configuration.addChild(release);
    execution.setConfiguration(configuration);

    assertThatThrownBy(() -> EliderTestCompilationEvidence.require(session, selected))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("successful test compilation");
    EliderTestCompilationEvidence.complete(session, selected, execution);

    assertAll(
        "compiler evidence is scoped to the project and session",
        () -> EliderTestCompilationEvidence.require(session, selected),
        () ->
            assertThat(EliderTestCompilationEvidence.compilerConfiguration(session, selected))
                .contains("3.13.0", "default-testCompile", "<release>21</release>"),
        () ->
            assertThatThrownBy(() -> EliderTestCompilationEvidence.require(session, other))
                .isInstanceOf(IllegalStateException.class),
        () ->
            assertThatThrownBy(
                    () -> EliderTestCompilationEvidence.compilerConfiguration(session(), selected))
                .isInstanceOf(IllegalStateException.class));

    EliderTestCompilationEvidence.clear(session);
    assertThatThrownBy(() -> EliderTestCompilationEvidence.require(session, selected))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void scopesCleanAndPreparedEvidenceAndDistinguishesNoAddition() throws Exception {
    final MavenSession session = session();
    final MavenProject selected = project("selected");
    final MavenProject other = project("other");
    final Path addition = temporaryDirectory.resolve("addition.jar");

    assertAll(
        "missing phase evidence",
        () -> assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isFalse(),
        () ->
            assertThatThrownBy(
                    () -> EliderTestCompilationEvidence.expectedAddition(session, selected))
                .isInstanceOf(IllegalStateException.class));
    EliderTestCompilationEvidence.markClean(session, selected);
    EliderTestCompilationEvidence.prepared(session, selected, Optional.empty());
    assertAll(
        "empty preparation is a valid, project-scoped result",
        () -> assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isTrue(),
        () -> assertThat(EliderTestCompilationEvidence.cleaned(session, other)).isFalse(),
        () ->
            assertThat(EliderTestCompilationEvidence.expectedAddition(session, selected)).isEmpty(),
        () ->
            assertThatThrownBy(() -> EliderTestCompilationEvidence.expectedAddition(session, other))
                .isInstanceOf(IllegalStateException.class));

    EliderTestCompilationEvidence.prepared(session, selected, Optional.of(addition));
    assertThat(EliderTestCompilationEvidence.expectedAddition(session, selected))
        .contains(addition);
    EliderTestCompilationEvidence.clear(session);
    assertAll(
        "clear removes prepared evidence but retains clean phase evidence",
        () ->
            assertThatThrownBy(
                    () -> EliderTestCompilationEvidence.expectedAddition(session, selected))
                .isInstanceOf(IllegalStateException.class),
        () -> assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isTrue());
  }

  @Test
  void skippedCleanCannotGrantFreshOutputProvenance() throws Exception {
    final MavenSession session = session();
    final MavenProject selected = project("skipped-clean");
    final Path mainOutput = Path.of(selected.getBuild().getOutputDirectory());
    final Path testOutput = Path.of(selected.getBuild().getTestOutputDirectory());
    Files.createDirectories(mainOutput);
    Files.createDirectories(testOutput);

    EliderTestCompilationEvidence.markClean(session, selected);
    assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isFalse();

    Files.delete(testOutput);
    EliderTestCompilationEvidence.markClean(session, selected);
    assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isFalse();

    Files.delete(mainOutput);
    EliderTestCompilationEvidence.markClean(session, selected);
    assertThat(EliderTestCompilationEvidence.cleaned(session, selected)).isTrue();
  }

  private MavenProject project(final String artifactId) throws IOException {
    final Path folder = Files.createDirectory(temporaryDirectory.resolve(artifactId));
    final MavenProject project = new MavenProject();
    project.setGroupId("fixture");
    project.setArtifactId(artifactId);
    project.setVersion("1");
    project.setFile(Files.createFile(folder.resolve("pom.xml")).toFile());
    final Build build = new Build();
    build.setOutputDirectory(folder.resolve("target/classes").toString());
    build.setTestOutputDirectory(folder.resolve("target/test-classes").toString());
    project.setBuild(build);
    return project;
  }

  private static MavenSession session() {
    return new MavenSession(
        null, new DefaultRepositorySystemSession(), new DefaultMavenExecutionRequest(), null);
  }
}
