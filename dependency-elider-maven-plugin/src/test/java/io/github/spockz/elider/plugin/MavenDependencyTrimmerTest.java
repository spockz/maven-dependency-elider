/* WHY: Verifies that trimming consumes the invocation scan so archive metadata is not read
 * twice. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies retained-JAR trimming uses the supplied invocation evidence. */
@SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
final class MavenDependencyTrimmerTest {
  /** Artifact identity shared by the test archive and Maven project. */
  private static final String ARTIFACT_ID = "runtime";

  /** Group shared by the fixture artifacts. */
  private static final String GROUP_ID = "org.example";

  /** Version shared by the fixture artifacts. */
  private static final String VERSION = "1.0";

  /** JAR type shared by fixture coordinates. */
  private static final String JAR_TYPE = "jar";

  /** Temporary workspace for compiled JAR fixtures. */
  @TempDir private Path tempDir;

  /** Creates the trimmer test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenDependencyTrimmerTest() {}

  @Test
  void serviceFinishConsumesPreparedDynamicRootsWithoutRescanningJar() throws Exception {
    final Path jar = compileJar();
    final Artifact artifact = runtimeArtifact(jar);
    final MavenProject project = project(artifact);
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, "sample.Keep\n");
    final AtomicInteger scans = new AtomicInteger();
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            new ElisionAnalysisModel.CompletenessOptions(false, false, false, true),
            new ElisionAnalysisModel.TrimOptions(
                true,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.MIN_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new ElisionAnalysisModel.DynamicRootOptions(true));
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            project,
            options,
            (path, context) -> {
              scans.incrementAndGet();
              return new DependencyDynamicRoots.RootScan(Set.of("sample.Dynamic"), true);
            });
    final ElisionAnalysisModel.Analysis analysis = service.finish(prepared);
    final TrimResult result = analysis.trimResult();
    assertThat(result.records()).hasSize(1);
    final ArtifactTrimRecord record = result.records().getFirst();
    final boolean keepPresent;
    final boolean dynamicPresent;
    final boolean dropPresent;
    try (JarFile trimmed = new JarFile(record.trimmedPath().toFile())) {
      keepPresent = trimmed.getEntry("sample/Keep.class") != null;
      dynamicPresent = trimmed.getEntry("sample/Dynamic.class") != null;
      dropPresent = trimmed.getEntry("sample/Drop.class") != null;
    }
    final TrimRequest request =
        TrimRequestFactory.fromPreparedAnalysis(
            prepared,
            prepared.rawDecision().retainedArtifacts(),
            prepared.pruningRequiredClasses());
    final TrimRequest missingScan =
        new TrimRequest(
            request.project(),
            request.session(),
            request.environment(),
            request.candidates(),
            new TrimScanInputs(request.scanInputs().classIndex(), Map.of()),
            request.retainedCoordinates(),
            request.evidence(),
            request.policy(),
            request.cacheProducerIdentity());

    assertAll(
        "the effective service path reuses prepared dynamic roots and requires a full scan set",
        () -> assertThat(scans).hasValue(1),
        () -> assertThat(prepared.dynamicRootInputs().classNames()).contains("sample.Dynamic"),
        () -> org.junit.jupiter.api.Assertions.assertTrue(keepPresent, "kept class remains"),
        () -> org.junit.jupiter.api.Assertions.assertTrue(dynamicPresent, "dynamic class remains"),
        () -> org.junit.jupiter.api.Assertions.assertFalse(dropPresent, "unused class is removed"),
        () ->
            assertThatThrownBy(
                    () -> MavenDependencyTrimmer.analyzeInMemory(missingScan, Map.of(), Set.of()))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Missing dynamic-root scan for full inventory JAR"));
  }

  private Path compileJar() throws IOException {
    final Path jar = tempDir.resolve("runtime.jar");
    final Path sourceDirectory = tempDir.resolve("sources");
    return io.github.spockz.elider.test.CompilationFixtureSupport.compileToJar(
        jar,
        sourceDirectory,
        Map.of(
            "sample/Keep.java", "package sample; public class Keep {}\n",
            "sample/Dynamic.java", "package sample; public class Dynamic {}\n",
            "sample/Drop.java", "package sample; public class Drop {}\n"),
        null);
  }

  private static Artifact runtimeArtifact(final Path jar) {
    final Artifact artifact =
        new DefaultArtifact(
            GROUP_ID,
            ARTIFACT_ID,
            VERSION,
            ARTIFACT_ID,
            JAR_TYPE,
            null,
            new DefaultArtifactHandler("jar"));
    artifact.setFile(jar.toFile());
    return artifact;
  }

  private MavenProject project(final Artifact artifact) {
    final MavenProject project = new MavenProject();
    project.setArtifacts(Set.of(artifact));
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion(VERSION);
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("build").toString());
    project.setBuild(build);
    return project;
  }
}
