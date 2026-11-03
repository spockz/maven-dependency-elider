// WHY: Verifies that mrjarStrategy=classpath-only does not force root modular JARs
// into pass-through.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class TrimPassThroughPlannerTest {
  @TempDir Path temporaryDirectory;

  @Test
  void modularJarPassesThroughByDefaultWhenFailOnUnsupportedModuleInfoFalse() throws IOException {
    final Path modularJar = MultiReleaseProjectionFixtures.compileModularJar(temporaryDirectory);
    final ArtifactCoordinate coord = ArtifactCoordinate.of("org.example", "modular", "1.0");
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(null, coord, modularJar);

    final TrimRequest defaultRequest =
        requestWithStrategy(
            MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING, false, Set.of(coord), List.of(snapshot));
    final TrimPassThroughPlan plan = TrimPassThroughPlanner.passThroughPlan(defaultRequest);
    assertThat(plan.moduleInfoCoordinates()).contains(coord);
    assertThat(TrimPassThroughPlanner.passThroughCoordinate(defaultRequest, snapshot)).isTrue();
  }

  @Test
  void modularJarFailsWhenFailOnUnsupportedModuleInfoTrue() throws IOException {
    final Path modularJar = MultiReleaseProjectionFixtures.compileModularJar(temporaryDirectory);
    final ArtifactCoordinate coord = ArtifactCoordinate.of("org.example", "modular", "1.0");
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(null, coord, modularJar);

    final TrimRequest strictRequest =
        requestWithStrategy(
            MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING, true, Set.of(coord), List.of(snapshot));
    assertThatThrownBy(() -> TrimPassThroughPlanner.passThroughPlan(strictRequest))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported root module descriptor");
  }

  @Test
  void modularJarIsNotPassThroughWhenClasspathOnlyStrategySelected() throws IOException {
    final Path modularJar = MultiReleaseProjectionFixtures.compileModularJar(temporaryDirectory);
    final ArtifactCoordinate coord = ArtifactCoordinate.of("org.example", "modular", "1.0");
    final ElisionAnalysisModel.ArtifactSnapshot snapshot =
        new ElisionAnalysisModel.ArtifactSnapshot(null, coord, modularJar);

    final TrimRequest classpathOnlyRequest =
        requestWithStrategy(
            MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY, false, Set.of(coord), List.of(snapshot));
    final TrimPassThroughPlan plan = TrimPassThroughPlanner.passThroughPlan(classpathOnlyRequest);
    assertThat(plan.moduleInfoCoordinates()).doesNotContain(coord);
    assertThat(TrimPassThroughPlanner.passThroughCoordinate(classpathOnlyRequest, snapshot))
        .isFalse();
  }

  private static TrimRequest requestWithStrategy(
      final String mrjarStrategy,
      final boolean failOnUnsupportedModuleInfo,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidates) {
    final MavenProject project = new MavenProject();
    project.setFile(Path.of("pom.xml").toFile());
    final TrimPolicy policy =
        new TrimPolicy(
            List.of(),
            false,
            List.of(),
            failOnUnsupportedModuleInfo,
            mrjarStrategy,
            true,
            false,
            1);
    return new TrimRequest(
        project, null, null, candidates, null, retainedCoordinates, null, policy, Optional.empty());
  }
}
