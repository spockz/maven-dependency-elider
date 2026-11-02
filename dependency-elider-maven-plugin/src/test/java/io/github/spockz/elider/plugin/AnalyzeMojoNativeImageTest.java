/*
 * WHY: Keeps native-image policy checks separate from artifact analysis.
 */

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.AnalyzeMojoTestFieldSupport.set;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
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
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests native-image handling. JUnit supplies its implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class AnalyzeMojoNativeImageTest {
  /** JAR packaging type used by generated Maven artifacts. */
  private static final String JAR_TYPE = "jar";

  /** Holds generated archives and reports for the native-image scenarios. */
  @TempDir private Path tempDir;

  @Test
  // WHY: Output and artifact checks prove allowed arguments preserve inputs.
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UnitTestContainsTooManyAsserts"})
  void analyzeAcceptsPermissiveNativeImageArgsWithTrimmingDisabled()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Path archive = tempDir.resolve("native-image-analysis.jar");
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
      output.putNextEntry(new ZipEntry("used/Sample.class"));
      output.write(new byte[] {0});
      output.closeEntry();
      output.putNextEntry(new ZipEntry("META-INF/native-image/test/native-image.properties"));
      output.write(
          "Args = -H:UnknownOption=value\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            "native-image",
            "1.0",
            "compile",
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    artifact.setFile(archive.toFile());
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(Set.of(artifact)));
    final Path trace = tempDir.resolve("native-image-trace.lst");
    Files.writeString(trace, "used.Sample\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "trimJars", false);
    set(mojo, "reportFile", tempDir.resolve("native-image-analysis.json").toFile());

    mojo.execute();

    assertThat(project.getArtifacts()).contains(artifact);
    assertThat(artifact.getFile().toPath()).isEqualTo(archive);
  }

  @Test
  // WHY: Rejection must preserve dependency views and archive bytes.
  @SuppressWarnings({"PMD.LawOfDemeter", "PMD.UnitTestContainsTooManyAsserts"})
  void analyzeRejectsHiddenNativeImageIndirectionWithoutMutatingArtifacts()
      throws IOException, ReflectiveOperationException {
    final Path archive = tempDir.resolve("native-image-indirection-analysis.jar");
    try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(archive))) {
      output.putNextEntry(new ZipEntry("used/Sample.class"));
      output.write(new byte[] {0});
      output.closeEntry();
      output.putNextEntry(new ZipEntry("META-INF/native-image/test/native-image.properties"));
      output.write("Args = -J--patch-module=\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    final Artifact artifact =
        new DefaultArtifact(
            "org.example",
            "native-image-indirection",
            "1.0",
            "compile",
            JAR_TYPE,
            null,
            new DefaultArtifactHandler(JAR_TYPE));
    artifact.setFile(archive.toFile());
    final Set<Artifact> artifacts = new LinkedHashSet<>(Set.of(artifact));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(new LinkedHashSet<>(artifacts));
    final Path trace = tempDir.resolve("native-image-indirection-trace.lst");
    Files.writeString(trace, "used/Sample\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("native-image-indirection-analysis.json").toFile());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("native-image indirection")
        .hasMessageContaining("forwarded launcher indirection");
    assertThat(project.getArtifacts()).isSameAs(artifacts).containsExactly(artifact);
    assertThat(project.getDependencyArtifacts()).containsExactly(artifact);
    assertThat(artifact.getFile().toPath()).isEqualTo(archive);
  }
}
