// WHY: Proves Analyze's temporary MRJAR projections are operation-local and cleaned on every exit.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class AnalysisProjectionWorkspaceTest {
  @TempDir private Path temporaryDirectory;

  @Test
  void predictionProjectionDirectoryIsIsolatedAndRemovedAfterSuccessAndFailure() throws Exception {
    final MavenProject project = project();
    final Path existingProjectOutput =
        TrimPaths.analysisLibraryDirectory(project).resolve("sentinel.jar");
    Files.createDirectories(existingProjectOutput.getParent());
    Files.writeString(existingProjectOutput, "preserve");
    final Path completedDirectory;
    final Path archive = archive();
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "projection", "1", "jar", "", "compile");
    try (AnalysisProjectionWorkspace workspace = AnalysisProjectionWorkspace.create()) {
      completedDirectory = workspace.directory();
      assertThat(TrimPaths.analysisLibraryDirectory(project, environment(completedDirectory)))
          .isEqualTo(completedDirectory);
      final Path projection =
          MultiReleaseLibraryProjection.create(archive, coordinate, completedDirectory, 21);
      assertAll(
          "successful projection exists only in its operation workspace",
          () -> assertThat(projection).exists(),
          () -> assertThat(TrimPaths.classNames(projection)).contains("projection.Api"));
    }
    assertAll(
        "workspace cleanup preserves pre-existing project output",
        () -> assertThat(completedDirectory).doesNotExist(),
        () -> assertThat(existingProjectOutput).hasContent("preserve"));

    final Path failedDirectory;
    try (AnalysisProjectionWorkspace workspace = AnalysisProjectionWorkspace.create()) {
      failedDirectory = workspace.directory();
      final Path malformed = temporaryDirectory.resolve("malformed-mrjar.jar");
      Files.writeString(malformed, "not a zip archive");
      assertThatThrownBy(
              () ->
                  MultiReleaseLibraryProjection.create(malformed, coordinate, failedDirectory, 21))
          .isInstanceOf(java.io.IOException.class);
    }
    assertAll(
        "failed projection cleanup preserves pre-existing project output",
        () -> assertThat(failedDirectory).doesNotExist(),
        () -> assertThat(existingProjectOutput).hasContent("preserve"));
  }

  @Test
  void concurrentPredictionWorkspacesDoNotShareProjectionFiles() throws Exception {
    final Path archive = archive();
    final ArtifactCoordinate coordinate =
        new ArtifactCoordinate("org.example", "projection", "1", "jar", "", "compile");
    final CyclicBarrier bothProjected = new CyclicBarrier(2);
    try (var executor = Executors.newFixedThreadPool(2)) {
      final var first = executor.submit(() -> projectAndAwait(archive, coordinate, bothProjected));
      final var second = executor.submit(() -> projectAndAwait(archive, coordinate, bothProjected));
      assertAll(
          "parallel predictions use distinct scratch paths with the same semantic identity",
          () -> assertThat(first.get()).isNotEqualTo(second.get()),
          () ->
              assertThat(environment(first.get()).fingerprint())
                  .isEqualTo(environment(second.get()).fingerprint()),
          () -> assertThat(first.get()).doesNotExist(),
          () -> assertThat(second.get()).doesNotExist());
    }
  }

  private Path projectAndAwait(
      final Path archive, final ArtifactCoordinate coordinate, final CyclicBarrier bothProjected)
      throws Exception {
    try (AnalysisProjectionWorkspace workspace = AnalysisProjectionWorkspace.create()) {
      final Path projection =
          MultiReleaseLibraryProjection.create(archive, coordinate, workspace.directory(), 21);
      bothProjected.await(10, TimeUnit.SECONDS);
      assertAll(
          "concurrent projection is present and contains the expected class",
          () -> assertThat(projection).exists(),
          () -> assertThat(TrimPaths.classNames(projection)).contains("projection.Api"));
      return workspace.directory();
    }
  }

  private AnalysisEnvironment environment(final Path projectionDirectory) {
    return new AnalysisEnvironment(
        java.util.Map.of(),
        java.util.Map.of(),
        temporaryDirectory,
        AnalysisEnvironment.JdkToolchainState.UNSELECTED,
        projectionDirectory);
  }

  private MavenProject project() {
    final MavenProject project = new MavenProject();
    final org.apache.maven.model.Build build = new org.apache.maven.model.Build();
    build.setDirectory(temporaryDirectory.resolve("target").toString());
    project.setBuild(build);
    return project;
  }

  private Path archive() throws Exception {
    final Path base =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "projection-base",
            8,
            "package projection; public class Api { public static String value() { "
                + "return \"base\"; } }");
    final Path versioned =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "projection-v21",
            21,
            "package projection; public class Api { public static String value() { "
                + "return \"upper\"; } }");
    final Path versionNine =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "projection-v9",
            9,
            "package projection; public class Api { public static String value() { "
                + "return \"nine\"; } }");
    final Path versionNineOnly =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory, "projection-v9-only", 9, "package projection; class NineOnly {}");
    final Path versionTwentyOneOnly =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "projection-v21-only",
            21,
            "package projection; public class TwentyOneOnly {}");
    final Path baseTwentyOneOnly =
        MultiReleaseProjectionFixtures.compile(
            temporaryDirectory,
            "projection-base-v21-only",
            8,
            "package projection; public class TwentyOneOnly {}");
    return MultiReleaseProjectionFixtures.createMultiReleaseJar(
        temporaryDirectory,
        base,
        versionNine,
        versionNineOnly,
        versioned,
        versionTwentyOneOnly,
        baseTwentyOneOnly);
  }
}
