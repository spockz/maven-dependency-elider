// WHY: Verifies goal skipping and real artifact-view mutation through the Maven goal.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies goal skipping and trace-based artifact-view mutation. */
@SuppressWarnings({
  "PMD.AvoidAccessibilityAlteration",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods",
  "PMD.UnitTestContainsTooManyAsserts"
})
final class ElideMojoTest {
  /** Temporary directory for synthetic JARs and runtime traces. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  ElideMojoTest() {}

  @Test
  void skipReturnsWithoutAccessingProjectState() throws ReflectiveOperationException {
    final ElideMojo mojo = new ElideMojo();
    final Field skip = ElideMojo.class.getDeclaredField("skip");
    skip.setAccessible(true);
    skip.setBoolean(mojo, true);

    assertThatCode(mojo::execute).doesNotThrowAnyException();
  }

  @Test
  void retainsCompileVisibleArtifactsInResolvedAndDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Artifact unused = artifact("unused", "unused/Idle.class");
    final Set<Artifact> resolved = new LinkedHashSet<>(List.of(used, unused));
    final Set<Artifact> direct = new LinkedHashSet<>(List.of(used, unused));
    final MavenProject project = new MavenProject();
    project.setArtifacts(resolved);
    project.setDependencyArtifacts(direct);
    execute(project, "used/Sample\n");

    assertThat(project.getArtifacts()).isNotSameAs(resolved);
    assertThat(project.getArtifacts()).containsExactlyInAnyOrder(used, unused);
    assertThat(project.getDependencyArtifacts()).isNotSameAs(direct);
    assertThat(project.getDependencyArtifacts()).containsExactlyInAnyOrder(used, unused);
    final Artifact addedLater = artifact("later", "later/Added.class");
    project.getArtifacts().add(addedLater);
    project.getDependencyArtifacts().add(addedLater);
    assertThat(project.getArtifacts()).contains(addedLater);
    assertThat(project.getDependencyArtifacts()).contains(addedLater);
  }

  @Test
  void preservesAbsentAndPresentEmptyDirectViews()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject absent = project(used, null);
    final MavenProject presentEmpty = project(used, new LinkedHashSet<>());

    execute(absent, "used/Sample\n");
    execute(presentEmpty, "used/Sample\n");

    assertThat(absent.getDependencyArtifacts()).isNull();
    assertThat(presentEmpty.getDependencyArtifacts()).isEmpty();
  }

  @Test
  void invalidTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final Artifact unused = artifact("unused", "unused/Idle.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used, unused)), unused);
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();

    assertThatThrownBy(() -> execute(project, "missing/Sample\n"))
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used, unused);
    assertThat(project.getDependencyArtifacts())
        .isSameAs(directBefore)
        .containsExactly(used, unused);
  }

  @Test
  void missingTraceFailsWithoutChangingEitherArtifactView()
      throws IOException, ReflectiveOperationException {
    final Artifact used = artifact("used", "used/Sample.class");
    final MavenProject project = project(used, new LinkedHashSet<>(List.of(used)));
    final Set<Artifact> resolvedBefore = project.getArtifacts();
    final Set<Artifact> directBefore = project.getDependencyArtifacts();
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("At least one supported trace input is required");
    assertThat(project.getArtifacts()).isSameAs(resolvedBefore).containsExactly(used);
    assertThat(project.getDependencyArtifacts()).isSameAs(directBefore).containsExactly(used);
  }

  private MavenProject project(final Artifact resolved, final Set<Artifact> direct) {
    return project(resolved, direct, null);
  }

  private MavenProject project(
      final Artifact resolved, final Set<Artifact> direct, final Artifact additionalResolved) {
    final MavenProject project = new MavenProject();
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(resolved));
    if (additionalResolved != null) {
      artifacts.add(additionalResolved);
    }
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(direct);
    return project;
  }

  private void execute(final MavenProject project, final String traceContent)
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, traceContent);
    final ElideMojo mojo = new ElideMojo();
    mojo.setLog(new SystemStreamLog());
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("elide-report.json").toFile());
    mojo.execute();
  }

  private Artifact artifact(final String artifactId, final String classEntry) throws IOException {
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            artifactId,
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(writeJar(artifactId + ".jar", classEntry).toFile());
    return artifact;
  }

  private Path writeJar(final String name, final String classEntry) throws IOException {
    final Path jar = tempDir.resolve(name);
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(jar))) {
      output.putNextEntry(new ZipEntry(classEntry));
      output.write(new byte[] {0});
      output.closeEntry();
    }
    return jar;
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }
}
