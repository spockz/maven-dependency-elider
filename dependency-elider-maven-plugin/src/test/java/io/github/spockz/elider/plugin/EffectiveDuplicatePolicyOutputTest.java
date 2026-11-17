/* WHY: Exercises duplicate-root retention through effective analysis and cached archive output. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.plugin.DuplicateClassPolicy.Action;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Keeps duplicate policy assertions at the effective trim and cache boundary. */
@SuppressWarnings("PMD.CouplingBetweenObjects")
final class EffectiveDuplicatePolicyOutputTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Class root promoted solely by duplicate policy. */
  private static final String EXTRA_CLASS = "closure.a.Extra";

  /** Unrelated class removed from the first owner. */
  private static final String UNUSED_A = "closure/a/Unused.class";

  /** Unrelated class removed from the second owner. */
  private static final String UNUSED_B = "closure/b/Unused.class";

  /** Dotted class name reported by root analysis for the first owner. */
  private static final String UNUSED_ROOT_A = "closure.a.Unused";

  /** Dotted class name reported by root analysis for the second owner. */
  private static final String UNUSED_ROOT_B = "closure.b.Unused";

  /** Suffix used by the expected archive entries. */
  private static final String CLASS_SUFFIX = ".class";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* package */ EffectiveDuplicatePolicyOutputTest() {
    super();
  }

  @Test
  void effectiveTrimPreservesUnreachableDuplicateInEveryOwnerAndCachesThatOutput()
      throws Exception {
    final Fixture fixture = fixtureWithDuplicateAndUnusedSecond();
    final Path trace = temporaryDirectory.resolve("duplicate-effective.lst");
    Files.writeString(trace, "closure/a/Entry\nclosure/b/Middle\n");
    final DuplicateClassPolicy duplicates =
        new DuplicateClassPolicy(List.of(), List.of(EXTRA_CLASS));
    final ElisionAnalysisModel.AnalysisOptions defaults =
        MavenElisionServiceEffectiveAnalysisFixtures.options(List.of(trace.toFile()), null, true);
    final ElisionAnalysisModel.TrimOptions baseTrim = defaults.trim();
    final ElisionAnalysisModel.TrimOptions trim =
        new ElisionAnalysisModel.TrimOptions(
            baseTrim.enabled(),
            baseTrim.explicitRoots(),
            baseTrim.failOnUnsupportedMultiRelease(),
            baseTrim.passThroughArtifacts(),
            baseTrim.failOnUnsupportedModuleInfo(),
            1,
            baseTrim.mrjarStrategy(),
            MavenPluginDescriptorFixtures.releasedProducerResolution(),
            duplicates);
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            defaults.traceFiles(),
            defaults.retainedArtifacts(),
            defaults.banishedDependencies(),
            defaults.productionOutput(),
            defaults.session(),
            defaults.completeness(),
            trim,
            defaults.dynamicRoots());
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis raw =
        service.prepare(fixture.mavenProject(), options);
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        MavenElisionServiceEffectiveAnalysisFixtures.withBinding(
            raw,
            new MavenElisionGraphBinding.Result(
                evaluation,
                raw.graphBinding().inventoryFingerprint(),
                raw.graphBinding().operationFingerprint(),
                pair));
    final ElisionAnalysisModel.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final Set<String> traceRoots = raw.trace().loadedClassesDotFormat();
    final Set<String> sourceRoots = raw.sourceRequiredClasses();
    final Set<String> pruningRoots = raw.pruningRequiredClasses();
    final Set<ArtifactCoordinate> unchanged = effective.forcedUnchangedCoordinates();
    final Set<String> rootsA =
        effective.trimAnalysis().candidateRoots().get(fixture.coordinate("a"));
    final Set<String> rootsB =
        effective.trimAnalysis().candidateRoots().get(fixture.coordinate("b"));
    final TrimResult cold = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final TrimResult warm = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    final ArtifactTrimRecord coldA = record(cold, fixture.coordinate("a"));
    final ArtifactTrimRecord coldB = record(cold, fixture.coordinate("b"));
    final ArtifactTrimRecord warmA = record(warm, fixture.coordinate("a"));
    final ArtifactTrimRecord warmB = record(warm, fixture.coordinate("b"));
    final Set<String> coldEntriesForA = archiveEntries(coldA);
    final Set<String> coldEntriesForB = archiveEntries(coldB);
    final Set<String> warmEntriesForA = archiveEntries(warmA);
    final Set<String> warmEntriesForB = archiveEntries(warmB);

    assertAll(
        "duplicate-policy roots survive effective analysis, output writing, and cache reuse",
        () ->
            assertAll(
                "duplicate roots are not independently live before duplicate policy is applied",
                () -> assertThat(traceRoots).doesNotContain(EXTRA_CLASS),
                () ->
                    assertThat(sourceRoots)
                        .doesNotContain(EXTRA_CLASS, UNUSED_ROOT_A, UNUSED_ROOT_B),
                () ->
                    assertThat(pruningRoots)
                        .doesNotContain(EXTRA_CLASS, UNUSED_ROOT_A, UNUSED_ROOT_B),
                () ->
                    assertThat(unchanged)
                        .doesNotContain(fixture.coordinate("a"), fixture.coordinate("b")),
                () -> assertThat(rootsA).contains(EXTRA_CLASS).doesNotContain(UNUSED_ROOT_A),
                () -> assertThat(rootsB).contains(EXTRA_CLASS).doesNotContain(UNUSED_ROOT_B)),
        () ->
            assertAll(
                "effective outputs retain duplicate copies, prune unrelated classes, and reuse"
                    + " cache",
                () ->
                    org.junit.jupiter.api.Assertions.assertEquals(
                        0, cold.cacheHits(), "cold output stage has no cache hits"),
                () ->
                    org.junit.jupiter.api.Assertions.assertTrue(
                        warm.cacheHits() > 0, "warm output stage reuses cached output"),
                () ->
                    assertThat(warm.toleratedDuplicates())
                        .containsExactlyElementsOf(cold.toleratedDuplicates()),
                () ->
                    assertThat(coldA.trimmedPath()).isNotEqualTo(fixture.snapshot("a").filePath()),
                () ->
                    assertThat(coldB.trimmedPath()).isNotEqualTo(fixture.snapshot("b").filePath()),
                () ->
                    assertThat(ArtifactDigests.read(coldA.trimmedPath()).sha256())
                        .isNotEqualTo(coldA.originalSha256()),
                () ->
                    assertThat(ArtifactDigests.read(coldB.trimmedPath()).sha256())
                        .isNotEqualTo(coldB.originalSha256()),
                () ->
                    assertThat(cold.toleratedDuplicates())
                        .anySatisfy(
                            duplicate ->
                                assertAll(
                                    () -> assertThat(duplicate.className()).isEqualTo(EXTRA_CLASS),
                                    () ->
                                        assertThat(duplicate.owners())
                                            .containsExactlyInAnyOrder(
                                                fixture.coordinate("a"), fixture.coordinate("b")),
                                    () ->
                                        assertThat(duplicate.action())
                                            .isEqualTo(Action.TRIM_OTHER_CLASSES))),
                () ->
                    assertThat(coldEntriesForA)
                        .contains(
                            EXTRA_CLASS.replace('.', '/') + CLASS_SUFFIX, "closure/a/Entry.class"),
                () -> assertThat(coldEntriesForA).doesNotContain(UNUSED_A),
                () ->
                    assertThat(coldEntriesForB)
                        .contains(
                            EXTRA_CLASS.replace('.', '/') + CLASS_SUFFIX, "closure/b/Middle.class"),
                () -> assertThat(coldEntriesForB).doesNotContain(UNUSED_B),
                () ->
                    assertThat(warmEntriesForA)
                        .contains(
                            EXTRA_CLASS.replace('.', '/') + CLASS_SUFFIX, "closure/a/Entry.class"),
                () -> assertThat(warmEntriesForA).doesNotContain(UNUSED_A),
                () ->
                    assertThat(warmEntriesForB)
                        .contains(
                            EXTRA_CLASS.replace('.', '/') + CLASS_SUFFIX, "closure/b/Middle.class"),
                () -> assertThat(warmEntriesForB).doesNotContain(UNUSED_B)),
        () -> assertFailedBatchStagingPreservesPriorFiles(effective));
  }

  private void assertFailedBatchStagingPreservesPriorFiles(
      final ElisionAnalysisModel.EffectiveAnalysis effective) throws IOException {
    final ElisionAnalysisModel.PreparedAnalysis prepared = effective.prepared();
    final TrimRequest request =
        TrimRequestFactory.fromPreparedAnalysis(
            prepared,
            effective.effectiveDecision().retainedArtifacts(),
            prepared.sourceRequiredClasses());
    final TrimGenerationPublisher.EffectiveOutputPlan outputPlan =
        new TrimGenerationPublisher.EffectiveOutputPlan(
            prepared,
            effective.trimAnalysis(),
            TrimRootPlanner.artifactRootKeys(
                prepared.resolvedSnapshots(), effective.trimAnalysis().candidateRoots()),
            effective.forcedUnchangedCoordinates(),
            effective.effectiveDecision().retainedArtifacts(),
            effective.inventoryFingerprint(),
            prepared.directInputFingerprint(),
            effective.operationFingerprint(),
            prepared.productionOutputFingerprint(),
            prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
            prepared.options().trim().explicitRoots(),
            prepared.options().trim().passThroughArtifacts(),
            prepared.options().completeness().sourceRootsComplete(),
            prepared.options().completeness().productionClassesComplete(),
            prepared.options().trim().mrjarStrategy(),
            prepared.options().trim().failOnUnsupportedModuleInfo());
    final TrimPassThroughPlan passThrough = TrimPassThroughPlanner.passThroughPlan(request);
    final TrimCandidatePlanner.CandidatePlan planned =
        EffectiveCandidatePlanner.effectiveCandidatePlan(
            prepared.project(),
            passThrough.retainedLibraries(),
            passThrough.retained(),
            prepared.index().classesByArtifact(),
            outputPlan);
    TrimCandidatePlanner.assignEffectiveAnalyses(planned, effective.trimAnalysis());
    final Map<String, TrimCandidate> byArtifact =
        planned.work().stream()
            .collect(
                Collectors.toMap(
                    candidate -> candidate.archive().snapshot().coordinate().artifactId(),
                    candidate -> candidate));
    final TrimCandidate candidateA = byArtifact.get("a");
    final TrimCandidate candidateB = byArtifact.get("b");
    final Path sourceDirectory = candidateB.archive().snapshot().filePath().getParent();
    final Path priorOutputA = sourceDirectory.resolve("prior-a-output.jar");
    Files.writeString(priorOutputA, "prior A output");
    final TrimCandidate stagedA = candidateWithOutput(candidateA, priorOutputA);
    final TrimCandidate stagedB =
        candidateWithOutput(candidateB, candidateB.archive().snapshot().filePath());
    final Path manifest = EffectiveOutputCacheTestFiles.cacheManifest(prepared.project());
    final byte[] priorManifest = Files.readAllBytes(manifest);
    final byte[] priorOriginalB = Files.readAllBytes(stagedB.archive().snapshot().filePath());
    final Map<Path, ArtifactDigests> digests =
        Map.of(
            stagedA.archive().snapshot().filePath(),
            ArtifactDigests.read(stagedA.archive().snapshot().filePath()),
            stagedB.archive().snapshot().filePath(),
            ArtifactDigests.read(stagedB.archive().snapshot().filePath()));
    final List<Path> stagedTemps;
    try {
      try (EffectiveOutputStaging staging = new EffectiveOutputStaging(sourceDirectory)) {
        assertThatThrownBy(
                () -> staging.prepareOutputs(List.of(stagedA, stagedB), digests, outputPlan, 1))
            .isInstanceOf(IOException.class)
            .hasMessageContaining("Trimmed JAR must not overwrite its original");
      }
    } finally {
      try (java.util.stream.Stream<Path> paths = Files.list(sourceDirectory)) {
        stagedTemps =
            paths.filter(path -> path.getFileName().toString().startsWith(".trimmed-")).toList();
      }
    }
    assertAll(
        "a second-candidate preparation failure discards temporary output only",
        () -> assertThat(Files.readString(priorOutputA)).isEqualTo("prior A output"),
        () ->
            assertThat(Files.readAllBytes(stagedB.archive().snapshot().filePath()))
                .containsExactly(priorOriginalB),
        () -> assertThat(Files.readAllBytes(manifest)).containsExactly(priorManifest),
        () -> assertThat(stagedTemps).isEmpty());
  }

  private static Set<String> archiveEntries(final ArtifactTrimRecord record) throws IOException {
    try (JarFile archive = new JarFile(record.trimmedPath().toFile())) {
      return archive.stream()
          .filter(entry -> !entry.isDirectory())
          .map(JarEntry::getName)
          .collect(Collectors.toUnmodifiableSet());
    }
  }

  private static ArtifactTrimRecord record(
      final TrimResult result, final ArtifactCoordinate coordinate) {
    return result.records().stream()
        .filter(trimRecord -> trimRecord.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow(
            () ->
                new AssertionError(
                    "No trim record for " + coordinate + "; records=" + result.records()));
  }

  private static TrimCandidate candidateWithOutput(final TrimCandidate source, final Path output) {
    final TrimCandidate candidate =
        new TrimCandidate(
            source.archive().snapshot(),
            source.archive().classes(),
            source.roots(),
            output,
            source.archive().multiRelease(),
            source.archive().logicalClassCount(),
            source.archive().upperTierClasses());
    candidate.analysis(source.analysis());
    return candidate;
  }
}
