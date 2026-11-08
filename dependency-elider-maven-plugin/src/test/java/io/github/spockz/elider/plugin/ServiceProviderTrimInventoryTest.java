/* WHY: Pins provider ownership across trimmed, unchanged, and upper-tier archives. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ServiceProviderTrimInventory.ServiceProviderInventory;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer.TrimAnalysis;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;

/** Covers global provider ownership decisions. */
final class ServiceProviderTrimInventoryTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Entry class used to reach the fixture's first artifact. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Provider duplicated in the first candidate and second retained artifact. */
  private static final String DUPLICATE_PROVIDER = "closure.a.Extra";

  /** Provider present only in the candidate's effective upper MRJAR tier. */
  private static final String UPPER_PROVIDER = "closure.a.UpperProvider";

  /** Class owned only by the unchanged second archive's versioned tier. */
  private static final String PASS_THROUGH_UPPER_PROVIDER = "closure.b.Unused";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* package */ ServiceProviderTrimInventoryTest() {
    super();
  }

  @Test
  void retainedInventoryIncludesUnchangedDuplicateOwnersAndCandidateUpperTiers() throws Exception {
    final Fixture fixture = fixtureWithDuplicateAndUnusedSecond();
    final Path trace = temporaryDirectory.resolve("inventory.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final List<Artifact> projectArtifacts = fixture.projectArtifactValues();
    final MavenProject project = fixture.projectValue();
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots = fixture.snapshotValues();
    final Artifact secondArtifact = projectArtifacts.get(1);
    final Path secondArchive = RuntimeEvidenceGoalFixture.artifactPath(secondArtifact);
    final Path passThroughMrjar =
        RuntimeEvidenceArchiveFixture.addUpperOnlyClass(
            secondArchive, temporaryDirectory.resolve("pass-through-mr.jar"));
    projectArtifacts.get(1).setFile(passThroughMrjar.toFile());
    project.setArtifacts(Set.copyOf(projectArtifacts));
    project.getProperties().setProperty("maven.compiler.release", "11");
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        new MavenElisionService()
            .prepare(
                project,
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, true));
    final ArtifactClassIndex index = prepared.index();
    final Map<ArtifactFileRef, Set<String>> classesByArtifact = index.classesByArtifact();
    final ElisionAnalysisModel.ArtifactSnapshot candidateSnapshot =
        prepared.resolvedSnapshots().stream()
            .filter(snapshot -> "a".equals(snapshot.coordinate().artifactId()))
            .findFirst()
            .orElseThrow();
    final ArtifactCoordinate candidateCoordinate = candidateSnapshot.coordinate();
    final ArtifactFileRef candidateRef =
        classesByArtifact.keySet().stream()
            .filter(reference -> reference.coordinate().equals(candidateCoordinate))
            .findFirst()
            .orElseThrow();
    final Set<ArtifactCoordinate> allRetained =
        snapshots.stream()
            .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
            .collect(java.util.stream.Collectors.toUnmodifiableSet());
    final Set<String> candidateClasses = classesByArtifact.get(candidateRef);
    final TrimCandidate candidate =
        new TrimCandidate(
            candidateSnapshot,
            candidateClasses,
            Set.of(ENTRY_CLASS),
            Path.of("candidate-trimmed.jar"),
            true,
            candidateClasses.size(),
            Set.of(UPPER_PROVIDER));
    candidate.analysis(
        new TrimAnalysis(candidateClasses.size(), Set.of(ENTRY_CLASS), Set.of(ENTRY_CLASS)));
    final ElisionAnalysisModel.ArtifactSnapshot secondSnapshot = snapshots.get(1);
    final String secondCoordinate = secondSnapshot.coordinate().toString();
    final EffectiveOutputPlan candidatePlan =
        outputPlan(prepared, allRetained, List.of(secondCoordinate));
    final ServiceProviderInventory candidateInventory =
        ServiceProviderTrimInventory.serviceProviderInventory(candidatePlan, List.of(candidate));
    final ElisionAnalysisModel.PreparedAnalysis trimOffPrepared =
        new MavenElisionService()
            .prepare(
                project,
                MavenElisionServiceEffectiveAnalysisFixtures.options(
                    List.of(trace.toFile()), null, false));
    final EffectiveOutputPlan trimOffPlan = outputPlan(trimOffPrepared, allRetained, List.of());
    final ServiceProviderInventory trimOffInventory =
        ServiceProviderTrimInventory.serviceProviderInventory(trimOffPlan, List.of());

    assertAll(
        "provider status includes every retained physical owner and effective tier",
        () -> assertThat(candidateInventory.ownedClasses()).contains(DUPLICATE_PROVIDER),
        () -> assertThat(candidateInventory.retainedClasses()).contains(DUPLICATE_PROVIDER),
        () -> assertThat(candidateInventory.retainedClasses()).contains(UPPER_PROVIDER),
        () -> assertThat(candidateInventory.ownedClasses()).contains(PASS_THROUGH_UPPER_PROVIDER),
        () ->
            assertThat(candidateInventory.retainedClasses()).contains(PASS_THROUGH_UPPER_PROVIDER),
        () -> assertThat(trimOffInventory.retainedClasses()).contains(DUPLICATE_PROVIDER),
        () -> assertThat(trimOffInventory.retainedClasses()).contains(PASS_THROUGH_UPPER_PROVIDER));
  }

  private static EffectiveOutputPlan outputPlan(
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final List<String> passThroughCoordinates) {
    return new EffectiveOutputPlan(
        prepared,
        new TrimAnalysisResult(
            Map.of(), Map.of(), Set.of(), 0, 11, 25, List.of(), List.of(11, 17), Map.of()),
        Map.of(),
        Set.of(),
        retainedCoordinates,
        "inventory",
        "direct",
        "operation",
        "production",
        Set.of(),
        List.of(),
        passThroughCoordinates,
        false,
        false,
        MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
        false);
  }
}
