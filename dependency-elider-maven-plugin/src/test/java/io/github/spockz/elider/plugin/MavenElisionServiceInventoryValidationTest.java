/* WHY: Proves preparation rejects changes to Maven's live resolved and direct artifact views. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.junit.jupiter.api.Test;

/** Verifies live Maven inventory validation around service analysis. */
final class MavenElisionServiceInventoryValidationTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Reused trace input keeps each Maven inventory mutation case equivalent. */
  private static final String TRACE = "closure/a/Entry\n";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenElisionServiceInventoryValidationTest() {
    super();
  }

  @Test
  void rejectsJarMutationDuringDynamicRootScanning() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("scan-mutation.lst");
    Files.writeString(trace, TRACE);
    final MavenElisionService.AnalysisOptions options = options(trace);

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .prepare(
                        fixture.mavenProject(),
                        options,
                        path -> {
                          if (fixture.snapshot("a").filePath().equals(path)) {
                            Files.writeString(path, "changed while scanning");
                          }
                          return new DependencyDynamicRoots.RootScan(Set.of(), true);
                        }))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Live Maven resolved artifact view changed");
  }

  @Test
  void rejectsResolvedFilePointerMutationDuringScanning() throws Exception {
    final Fixture fixture = fixture(false);
    final Path trace = temporaryDirectory.resolve("pointer-mutation.lst");
    Files.writeString(trace, TRACE);
    final Path replacement = temporaryDirectory.resolve("replacement-a.jar");
    Files.copy(fixture.snapshot("a").filePath(), replacement);
    final Artifact artifact =
        fixture.artifacts().stream()
            .filter(candidate -> "a".equals(candidate.getArtifactId()))
            .findFirst()
            .orElseThrow();

    assertThatThrownBy(
            () ->
                new MavenElisionService()
                    .prepare(
                        fixture.mavenProject(),
                        options(trace),
                        path -> {
                          if (fixture.snapshot("a").filePath().equals(path)) {
                            artifact.setFile(replacement.toFile());
                          }
                          return new DependencyDynamicRoots.RootScan(Set.of(), true);
                        }))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Live Maven resolved artifact view changed");
  }

  @Test
  void rejectsResolvedMembershipChangeBeforeEffectiveAnalysis() throws Exception {
    final Fixture fixture = fixture(false);
    fixture.mavenProject().setDependencyArtifacts(Set.copyOf(fixture.artifacts()));
    final Path trace = temporaryDirectory.resolve("membership-change.lst");
    Files.writeString(trace, TRACE);
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(fixture.mavenProject(), options(trace));
    fixture.mavenProject().setArtifacts(Set.of(fixture.artifacts().getFirst()));

    assertThatThrownBy(() -> service.finishAnalysis(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Live Maven resolved artifact view changed");
  }

  @Test
  void rejectsDirectMembershipChangeBeforeEffectiveAnalysis() throws Exception {
    final Fixture fixture = fixture(false);
    fixture.mavenProject().setDependencyArtifacts(Set.of(fixture.artifacts().getFirst()));
    final Path trace = temporaryDirectory.resolve("direct-membership-change.lst");
    Files.writeString(trace, TRACE);
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(fixture.mavenProject(), options(trace));
    fixture.mavenProject().setDependencyArtifacts(Set.copyOf(fixture.artifacts()));

    assertThatThrownBy(() -> service.finishAnalysis(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Live Maven direct artifact view changed");
  }

  private static MavenElisionService.AnalysisOptions options(final Path trace) {
    return new MavenElisionService.AnalysisOptions(
        List.of(trace.toFile()),
        List.of(),
        null,
        null,
        false,
        true,
        List.of(),
        false,
        List.of(),
        false,
        true);
  }
}
