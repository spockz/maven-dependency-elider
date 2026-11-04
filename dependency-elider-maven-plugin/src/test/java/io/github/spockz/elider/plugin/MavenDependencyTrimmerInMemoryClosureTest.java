/* WHY: Proves analyzer root routing and strict complete-inventory failure behavior. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Verifies strict in-memory scanning over complete candidate inventories. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.TooManyMethods"})
final class MavenDependencyTrimmerInMemoryClosureTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Trace entry class for the generated closure fixture. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Duplicate class shared by the first two fixture archives. */
  private static final String EXTRA_CLASS = "closure.a.Extra";

  /** Creates this focused behavior test group. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MavenDependencyTrimmerInMemoryClosureTest() {
    super();
  }

  @Test
  void scansPromotedArtifactAsProgramToDiscoverDroppedDependency() throws Exception {
    final Fixture fixture = fixture(false);
    final TrimAnalysisResult first =
        fixture.analyze(Set.of(fixture.coordinate("a")), Set.of(), Map.of());

    assertThat(first.reachableArtifacts()).contains(fixture.coordinate("b"));
    assertThat(first.reachableArtifacts()).doesNotContain(fixture.coordinate("c"));
    assertThat(first.candidateRoots().get(fixture.coordinate("a"))).contains(ENTRY_CLASS);

    final TrimAnalysisResult second =
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
    final TrimArtifactRootKey key =
        new TrimArtifactRootKey(fixture.coordinate("a"), path, ArtifactDigests.read(path).sha256());
    final TrimAnalysisResult result =
        fixture.analyze(
            Set.of(fixture.coordinate("a")), Set.of(), Map.of(key, Set.of(EXTRA_CLASS)));

    assertThat(result.candidateRoots().get(fixture.coordinate("a")))
        .contains(ENTRY_CLASS, EXTRA_CLASS);
    assertThat(result.candidateAnalyses().get(fixture.coordinate("a")).roots())
        .contains("closure/a/Extra");
  }

  @Test
  void routesTraceAndDynamicRootsOnlyToTheirOwningCandidateJar() throws Exception {
    final Fixture fixture = fixture(false);
    final Map<Path, Set<String>> dynamicRoots =
        Map.of(fixture.snapshot("b").filePath(), Set.of("closure/b/Middle"));

    final TrimAnalysisResult result =
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

    final TrimAnalysisResult result =
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

    final TrimAnalysisResult result =
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

    final TrimAnalysisResult result =
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
  void stillRejectsDuplicatesThatNoConfiguredPatternMatches() throws Exception {
    final Fixture fixture = fixture(true);
    final DuplicateClassPolicy unrelated =
        new DuplicateClassPolicy(List.of("closure.z.**"), List.of("closure.y.**"));

    assertThatThrownBy(() -> fixture.analyze(Set.of(fixture.coordinate("a")), unrelated))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate class owner")
        .hasMessageContaining(EXTRA_CLASS);
  }

  @Test
  void retainDuplicateClassOwnersKeepsEveryOwningJarWhole() throws Exception {
    final Fixture fixture = fixture(true);
    final DuplicateClassPolicy policy = new DuplicateClassPolicy(List.of(EXTRA_CLASS), List.of());

    final TrimAnalysisResult result =
        fixture.analyze(Set.of(fixture.coordinate("a"), fixture.coordinate("b")), policy);

    assertAll(
        () ->
            assertThat(result.candidateAnalyses())
                .as("owners of a retained duplicate are pass-through, never trimmed")
                .doesNotContainKeys(fixture.coordinate("a"), fixture.coordinate("b")),
        () ->
            assertThat(result.reachableArtifacts())
                .as("whole retained JARs are still scanned as programs")
                .contains(fixture.coordinate("c")));
  }

  @Test
  void retainDuplicateOwnerMayAlsoBeExplicitlySkipped() throws Exception {
    final Fixture fixture = fixture(true);
    final DuplicateClassPolicy policy = new DuplicateClassPolicy(List.of(EXTRA_CLASS), List.of());

    final TrimAnalysisResult result =
        fixture.analyzeDuplicateRoot(
            Set.of(fixture.coordinate("a"), fixture.coordinate("b")),
            policy,
            List.of("fixture:a:1.0"));

    assertAll(
        () ->
            assertThat(result.candidateAnalyses())
                .doesNotContainKeys(fixture.coordinate("a"), fixture.coordinate("b")),
        () -> assertThat(result.reachableArtifacts()).contains(fixture.coordinate("c")));
  }

  @Test
  void duplicateProvidedOwnerIsReportedAndKeepsCompileOwnerWhole() throws Exception {
    final Fixture fixture = fixtureWithProvidedDuplicate();
    final DuplicateClassPolicy policy = new DuplicateClassPolicy(List.of(EXTRA_CLASS), List.of());
    final Set<io.github.spockz.elider.model.ArtifactCoordinate> retained =
        Set.of(fixture.coordinate("a"), fixture.coordinate("b"));
    final TrimRequest request =
        new TrimRequest(
            fixture.project,
            null,
            fixture.snapshots,
            fixture.scanInputs,
            retained,
            new TrimEvidence(TraceData.of(Set.of(ENTRY_CLASS)), Set.of(), Set.of(), Set.of()),
            new TrimPolicy(
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                true,
                true,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                policy));

    final TrimAnalysisResult analysis = fixture.analyze(retained, policy);
    final List<DuplicateClasses.ToleratedDuplicate> duplicates =
        DuplicateClasses.resolveRetained(request);

    assertAll(
        () -> assertThat(analysis.candidateAnalyses()).doesNotContainKey(fixture.coordinate("a")),
        () ->
            assertThat(duplicates)
                .singleElement()
                .satisfies(
                    duplicate -> {
                      assertAll(
                          () -> assertThat(duplicate.className()).isEqualTo(EXTRA_CLASS),
                          () ->
                              assertThat(duplicate.owners())
                                  .containsExactlyInAnyOrder(
                                      fixture.coordinate("a"), fixture.coordinate("b")));
                    }));
  }

  @Test
  void trimDuplicateClassOwnersRootsTheDuplicateInEveryOwnerAndTrimsTheRest() throws Exception {
    final Fixture fixture = fixture(true);
    final DuplicateClassPolicy policy = new DuplicateClassPolicy(List.of(), List.of("closure.a.*"));

    final TrimAnalysisResult result =
        fixture.analyze(Set.of(fixture.coordinate("a"), fixture.coordinate("b")), policy);

    assertAll(
        () ->
            assertThat(result.candidateRoots().get(fixture.coordinate("a")))
                .contains(EXTRA_CLASS, ENTRY_CLASS),
        () ->
            assertThat(result.candidateRoots().get(fixture.coordinate("b")))
                .contains(EXTRA_CLASS)
                .doesNotContain(ENTRY_CLASS),
        () ->
            assertThat(result.candidateAnalyses())
                .containsKeys(fixture.coordinate("a"), fixture.coordinate("b")));
  }

  @Test
  void matchedDuplicateRescuesDroppedOwnerAndAppliesPolicyToRetainedOwner() throws Exception {
    final Fixture fixture = fixture(true);
    final Set<io.github.spockz.elider.model.ArtifactCoordinate> retained =
        Set.of(fixture.coordinate("b"));
    final TrimAnalysisResult result =
        fixture.analyzeDuplicateRoot(
            retained, new DuplicateClassPolicy(List.of(), List.of(EXTRA_CLASS)));
    final TrimAnalysisResult whole =
        fixture.analyzeDuplicateRoot(
            retained, new DuplicateClassPolicy(List.of(EXTRA_CLASS), List.of()));

    assertAll(
        () -> assertThat(result.candidateAnalyses()).containsKey(fixture.coordinate("b")),
        () ->
            assertThat(result.candidateRoots().get(fixture.coordinate("b"))).contains(EXTRA_CLASS),
        () -> assertThat(result.reachableArtifacts()).contains(fixture.coordinate("a")),
        () -> assertThat(whole.candidateAnalyses()).doesNotContainKey(fixture.coordinate("b")),
        () -> assertThat(whole.reachableArtifacts()).contains(fixture.coordinate("a")));
  }

  @Test
  void eachDuplicateVariantRetainsItsOwnExternalDependency() throws Exception {
    final Fixture fixture = fixtureWithDistinctDuplicateDependencies();
    final Set<io.github.spockz.elider.model.ArtifactCoordinate> retained =
        Set.of(fixture.coordinate("a"), fixture.coordinate("b"));

    final TrimAnalysisResult trimmed =
        fixture.analyzeDuplicateRoot(
            retained, new DuplicateClassPolicy(List.of(), List.of(EXTRA_CLASS)));
    final TrimAnalysisResult passedThrough =
        fixture.analyzeDuplicateRoot(
            retained, new DuplicateClassPolicy(List.of(EXTRA_CLASS), List.of()));
    final TrimAnalysisResult mixed =
        fixture.analyzeDuplicateRoot(
            retained,
            new DuplicateClassPolicy(List.of(), List.of(EXTRA_CLASS)),
            List.of("fixture:a:1.0"));

    assertAll(
        () ->
            assertThat(trimmed.candidateAnalyses())
                .containsKeys(fixture.coordinate("a"), fixture.coordinate("b")),
        () ->
            assertThat(trimmed.reachableArtifacts())
                .contains(fixture.coordinate("c"), fixture.coordinate("e")),
        () ->
            assertThat(passedThrough.candidateAnalyses())
                .doesNotContainKeys(fixture.coordinate("a"), fixture.coordinate("b")),
        () ->
            assertThat(passedThrough.reachableArtifacts())
                .contains(fixture.coordinate("c"), fixture.coordinate("e")),
        () ->
            assertThat(mixed.candidateAnalyses())
                .containsKey(fixture.coordinate("b"))
                .doesNotContainKey(fixture.coordinate("a")),
        () ->
            assertThat(mixed.reachableArtifacts())
                .contains(fixture.coordinate("c"), fixture.coordinate("e")));
  }

  @Test
  void analyzesRetainedMultiReleaseCandidateWithLogicalClassNames() throws Exception {
    final Fixture fixture = fixture(false);
    final Path multiRelease = fixture.addVersionedClassToC();

    assertThat(multiRelease).isRegularFile();
    final TrimAnalysisResult analysis =
        fixture.analyze(
            Set.of(fixture.coordinate("a"), fixture.coordinate("c")), Set.of(), Map.of());

    assertThat(analysis.candidateAnalyses()).containsKey(fixture.coordinate("c"));
    assertThat(analysis.candidateRoots().get(fixture.coordinate("c")))
        .contains("closure.c.Leaf")
        .noneMatch(name -> name.startsWith("META-INF.versions."));
  }
}
