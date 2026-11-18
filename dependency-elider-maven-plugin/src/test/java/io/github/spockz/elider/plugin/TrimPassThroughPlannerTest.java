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

/** Verifies pass-through planning for modular and multi-release JARs. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals"
})
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
  }

  @Test
  void parsesWildcardVersionAndClassifierInPassThroughCoordinates() throws IOException {
    final ArtifactCoordinate plain =
        new ArtifactCoordinate("org.example", "lib", "2.1.0", "jar", "", "compile");
    final ArtifactCoordinate shaded =
        new ArtifactCoordinate("org.example", "lib", "2.1.0", "jar", "shaded", "compile");
    final ArtifactCoordinate other =
        new ArtifactCoordinate("org.example", "other", "1.0", "jar", "linux", "compile");
    final List<ElisionAnalysisModel.ArtifactSnapshot> candidates =
        List.of(
            new ElisionAnalysisModel.ArtifactSnapshot(null, plain, null),
            new ElisionAnalysisModel.ArtifactSnapshot(null, shaded, null),
            new ElisionAnalysisModel.ArtifactSnapshot(null, other, null));

    final List<ElisionAnalysisModel.ArtifactSnapshot> byGroupArtifact =
        TrimPassThroughPlanner.parsePassThroughArtifacts(List.of("org.example:lib"), candidates);
    final List<ElisionAnalysisModel.ArtifactSnapshot> byVersionOnly =
        TrimPassThroughPlanner.parsePassThroughArtifacts(
            List.of("org.example:other:1.0"), candidates);
    final List<ElisionAnalysisModel.ArtifactSnapshot> byClassifierOnly =
        TrimPassThroughPlanner.parsePassThroughArtifacts(
            List.of("org.example:lib::jar:shaded"), candidates);
    final List<ElisionAnalysisModel.ArtifactSnapshot> emptyClassifierExplicit =
        TrimPassThroughPlanner.parsePassThroughArtifacts(
            List.of("org.example:lib:2.1.0:jar:"), candidates);

    org.junit.jupiter.api.Assertions.assertAll(
        () ->
            assertThat(byGroupArtifact)
                .extracting(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                .containsExactly(plain, shaded),
        () ->
            assertThat(byVersionOnly)
                .extracting(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                .containsExactly(other),
        () ->
            assertThat(byClassifierOnly)
                .extracting(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                .containsExactly(shaded),
        () ->
            assertThat(emptyClassifierExplicit)
                .extracting(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
                .containsExactly(plain),
        () ->
            assertThatThrownBy(() -> MavenArtifactIdentity.parsePassThrough("org.example"))
                .isInstanceOf(IllegalArgumentException.class),
        () ->
            assertThatThrownBy(() -> MavenArtifactIdentity.parsePassThrough("org.example:"))
                .isInstanceOf(IllegalArgumentException.class));
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
