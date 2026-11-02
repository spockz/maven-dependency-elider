/*
 * WHY: Proves Resolver-restored classpaths preserve attribution and leave the live model intact.
 */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests Resolver-restored compile artifacts. JUnit supplies the implicit constructor. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class DetachedResolverCompileClasspathTest {
  /** Holds the generated project and archive fixtures. */
  @TempDir private Path temporaryDirectory;

  @Test
  void resolverResultUsesMavenTypeHandlersForCompileAndNonClasspathArtifacts() throws IOException {
    final DetachedResolverCompileClasspathFixture.Fixture fixture =
        DetachedResolverCompileClasspathFixture.create(temporaryDirectory);
    final MavenProject live = fixture.live();
    final MavenAnalysisResolutionContext context = fixture.context();
    final MavenProject detached = context.project();
    final ProductionAnalysisInputs.CompilerInputs inputs = fixture.inputs();

    assertAll(
        "Resolver-restored compile classpath preserves attribution and leaves the live model alone",
        () -> assertThat(inputs.requiredClasses()).contains("org.example.api.Api"),
        () -> assertThat(inputs.compileVisibleCoordinates()).contains(fixture.coordinate()),
        () ->
            assertThat(detached.getCompileClasspathElements())
                .contains(fixture.library().toAbsolutePath().normalize().toString())
                .doesNotContain(
                    fixture.nonClasspathArchive().toAbsolutePath().normalize().toString()),
        () -> assertThat(detached).isNotSameAs(live),
        () -> assertThat(live.getArtifacts()).isEmpty(),
        () -> assertThat(live.getDependencyArtifacts()).isNull(),
        () ->
            assertThat(live.getDependencies())
                .singleElement()
                .satisfies(
                    dependency -> assertThat(dependency.getArtifactId()).isEqualTo("compile-api")));
  }
}
