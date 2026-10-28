/* WHY: Proves analyzer root routing and strict complete-inventory failure behavior. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies strict in-memory scanning over complete candidate inventories. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts"})
final class MavenDependencyTrimmerInMemoryClosureTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Trace entry class for the generated closure fixture. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenDependencyTrimmerInMemoryClosureTest() {
    super();
  }

  @Test
  void scansPromotedArtifactAsProgramToDiscoverDroppedDependency() throws Exception {
    final Fixture fixture = fixture(false);
    final MavenDependencyTrimmer.InMemoryAnalysis first =
        fixture.analyze(Set.of(fixture.coordinate("a")), Set.of(), Map.of());

    assertThat(first.reachableArtifacts()).contains(fixture.coordinate("b"));
    assertThat(first.reachableArtifacts()).doesNotContain(fixture.coordinate("c"));
    assertThat(first.candidateRoots().get(fixture.coordinate("a"))).contains(ENTRY_CLASS);

    final MavenDependencyTrimmer.InMemoryAnalysis second =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            Set.of(fixture.coordinate("b")),
            Map.of());

    assertThat(second.reachableArtifacts()).contains(fixture.coordinate("c"));
    assertThat(second.candidateAnalyses()).containsKey(fixture.coordinate("a"));
    assertThat(fixture.artifacts()).allSatisfy(artifact -> assertThat(artifact.getFile()).exists());
    assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist();
  }

  @Test
  void consumesAndValidatesExactPerArtifactDiscoveredRoots() throws Exception {
    final Fixture fixture = fixture(false);
    final Path path = fixture.snapshot("a").filePath();
    final MavenDependencyTrimmer.ArtifactRootKey key =
        new MavenDependencyTrimmer.ArtifactRootKey(
            fixture.coordinate("a"), path, ArtifactDigests.read(path).sha256());
    final MavenDependencyTrimmer.InMemoryAnalysis result =
        fixture.analyze(
            Set.of(fixture.coordinate("a")), Set.of(), Map.of(key, Set.of("closure.a.Extra")));

    assertThat(result.candidateRoots().get(fixture.coordinate("a")))
        .contains(ENTRY_CLASS, "closure.a.Extra");
    assertThat(result.candidateAnalyses().get(fixture.coordinate("a")).roots())
        .contains("closure/a/Extra");
  }

  @Test
  void routesTraceAndDynamicRootsOnlyToTheirOwningCandidateJar() throws Exception {
    final Fixture fixture = fixture(false);
    final Map<Path, Set<String>> dynamicRoots =
        Map.of(fixture.snapshot("b").filePath(), Set.of("closure/b/Middle"));

    final MavenDependencyTrimmer.InMemoryAnalysis result =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            Set.of(),
            Map.of(),
            dynamicRoots,
            List.of());

    assertThat(result.candidateRoots().get(fixture.coordinate("a")))
        .contains(ENTRY_CLASS)
        .doesNotContain("closure.b.Middle");
    assertThat(result.candidateRoots().get(fixture.coordinate("b")))
        .contains("closure.b.Middle")
        .doesNotContain(ENTRY_CLASS);
  }

  @Test
  void scansConfiguredPassThroughAndReportsItsRawDroppedReference() throws Exception {
    final Fixture fixture = fixture(false);

    final MavenDependencyTrimmer.InMemoryAnalysis result =
        fixture.analyze(
            Set.of(fixture.coordinate("a")),
            Set.of(fixture.coordinate("a")),
            Map.of(),
            Map.of(),
            List.of("fixture:a:1.0"));

    assertThat(result.reachableArtifacts()).contains(fixture.coordinate("b"));
  }

  @Test
  void analyzesRawRetainedCandidateAndFindsAnotherRawDrop() throws Exception {
    final Fixture fixture = fixture(false);

    final MavenDependencyTrimmer.InMemoryAnalysis result =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            Set.of(),
            Map.of(),
            Map.of(),
            List.of());

    assertThat(result.candidateRoots().get(fixture.coordinate("b"))).contains("closure.b.Middle");
    assertThat(result.reachableArtifacts()).contains(fixture.coordinate("c"));
  }

  @Test
  void forcedUnchangedProgramToleratesAnUnresolvedOptionalClassReference() throws Exception {
    final Fixture fixture = fixtureWithOptionalAsmReference();

    final MavenDependencyTrimmer.InMemoryAnalysis result =
        fixture.analyze(Set.of(fixture.coordinate("a")), Set.of(fixture.coordinate("a")), Map.of());

    assertThat(result.reachableArtifacts()).contains(fixture.coordinate("b"));
    assertThat(result.candidateAnalyses()).doesNotContainKey(fixture.coordinate("a"));
  }

  @Test
  void trimCandidateStillRejectsTheSameUnresolvedOptionalClassReference() throws Exception {
    final Fixture fixture = fixtureWithOptionalAsmReference();

    assertThatThrownBy(() -> fixture.analyze(Set.of(fixture.coordinate("a")), Set.of(), Map.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("org/objectweb/asm/Label");
  }

  @Test
  void rejectsDuplicateClassOwnersAcrossCompleteInventory() throws Exception {
    final Fixture fixture = fixture(true);

    assertThatThrownBy(() -> fixture.analyze(Set.of(fixture.coordinate("a")), Set.of(), Map.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate class owner");
  }

  @Test
  void keepsRetainedMultiReleaseJarAsUnchangedPassThrough() throws Exception {
    final Fixture fixture = fixture(false);
    final Path multiRelease = fixture.addVersionedClassToC();

    assertThat(multiRelease).isRegularFile();
    final MavenDependencyTrimmer.InMemoryAnalysis analysis =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("c")), Set.of(), Map.of());

    assertThat(analysis.candidateAnalyses()).doesNotContainKey(fixture.coordinate("c"));
    assertThat(analysis.candidateRoots()).doesNotContainKey(fixture.coordinate("c"));
  }
}
