/* WHY: Verifies effective trim publication preserves duplicate classes across release tiers. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.DuplicateClassPolicy.Action;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** Checks effective MRJAR output preserves duplicate classes. */
final class EffectiveDuplicateMultiReleaseOutputTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Duplicate class shared by archive tiers. */
  private static final String DUPLICATE_CLASS = "closure.a.Extra";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* package */ EffectiveDuplicateMultiReleaseOutputTest() {
    super();
  }

  @Test
  void effectiveOutputKeepsUpperTierDuplicateAndPrunesUnrelatedClasses() throws Exception {
    final Fixture fixture = fixtureWithDuplicateAndUnusedSecond(9);
    final Path secondPath = fixture.snapshot("b").filePath();
    final OwnerEntries entries = readOwner(secondPath);
    final byte[] unused =
        Files.readAllBytes(temporaryDirectory.resolve("classes/closure/b/Unused.class"));
    writeVersionedOwner(secondPath, entries.duplicate(), entries.middle(), unused, 21, true, true);
    final Path trace = temporaryDirectory.resolve("upper-tier-duplicate.lst");
    Files.writeString(trace, "closure/a/Entry\nclosure/b/Middle\n");
    final DuplicateClassPolicy duplicates =
        new DuplicateClassPolicy(List.of(), List.of(DUPLICATE_CLASS));
    final ElisionAnalysisModel.AnalysisOptions defaults =
        MavenElisionServiceEffectiveAnalysisFixtures.options(List.of(trace.toFile()), null, true);
    final ElisionAnalysisModel.TrimOptions baseTrim = defaults.trim();
    final ElisionAnalysisModel.TrimOptions trim =
        new ElisionAnalysisModel.TrimOptions(
            true,
            baseTrim.explicitRoots(),
            baseTrim.failOnUnsupportedMultiRelease(),
            baseTrim.passThroughArtifacts(),
            baseTrim.failOnUnsupportedModuleInfo(),
            baseTrim.workers(),
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
    final ElisionAnalysisModel.Analysis analysis = service.finishEffectiveOutputs(effective);
    final ArtifactTrimRecord outputA = record(analysis, fixture.coordinate("a"));
    final ArtifactTrimRecord outputB = record(analysis, fixture.coordinate("b"));
    final Set<String> entriesA = archiveEntries(outputA.trimmedPath());
    final Set<String> entriesB = archiveEntries(outputB.trimmedPath());

    assertAll(
        "tier-aware effective output preserves duplicates in their effective release views",
        () ->
            assertThat(effective.trimAnalysis().candidateRoots().get(fixture.coordinate("a")))
                .contains(DUPLICATE_CLASS, "closure.a.Entry"),
        () ->
            assertThat(effective.trimAnalysis().upperTierClasses().get(fixture.coordinate("b")))
                .contains(DUPLICATE_CLASS),
        () -> assertThat(outputA.retainedClasses()).isLessThan(outputA.totalClasses()),
        () -> assertThat(outputB.retainedClasses()).isLessThan(outputB.totalClasses()),
        () -> assertThat(entriesA).contains("closure/a/Extra.class", "closure/a/Entry.class"),
        () -> assertThat(entriesA).doesNotContain("closure/a/Unused.class"),
        () -> assertThat(entriesB).contains("closure/b/Middle.class"),
        () -> assertThat(entriesB).contains("META-INF/versions/21/closure/a/Extra.class"),
        () -> assertThat(entriesB).doesNotContain("closure/b/Unused.class"),
        () ->
            assertThat(analysis.trimResult().toleratedDuplicates())
                .anySatisfy(
                    duplicate ->
                        assertAll(
                            () -> assertThat(duplicate.className()).isEqualTo(DUPLICATE_CLASS),
                            () ->
                                assertThat(duplicate.action())
                                    .isEqualTo(Action.TRIM_OTHER_CLASSES))));
  }

  private static ArtifactTrimRecord record(
      final ElisionAnalysisModel.Analysis analysis, final ArtifactCoordinate coordinate) {
    return analysis.trimResult().records().stream()
        .filter(value -> value.coordinate().equals(coordinate))
        .findFirst()
        .orElseThrow();
  }

  private static Set<String> archiveEntries(final Path archivePath) throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.stream()
          .filter(entry -> !entry.isDirectory())
          .map(JarEntry::getName)
          .collect(Collectors.toUnmodifiableSet());
    }
  }

  private static OwnerEntries readOwner(final Path source) throws IOException {
    try (JarFile archive = new JarFile(source.toFile())) {
      try (InputStream duplicate =
              archive.getInputStream(archive.getJarEntry("closure/a/Extra.class"));
          InputStream middle =
              archive.getInputStream(archive.getJarEntry("closure/b/Middle.class"))) {
        return new OwnerEntries(duplicate.readAllBytes(), middle.readAllBytes());
      }
    }
  }

  private static void writeVersionedOwner(
      final Path target,
      final byte[] duplicate,
      final byte[] middle,
      final byte[] unused,
      final int release,
      final boolean multiRelease,
      final boolean includeBaseDuplicate)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", Boolean.toString(multiRelease));
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(target), manifest)) {
      output.putNextEntry(new JarEntry("closure/b/Middle.class"));
      output.write(middle);
      output.closeEntry();
      if (includeBaseDuplicate) {
        output.putNextEntry(new JarEntry("closure/a/Extra.class"));
        output.write(duplicate);
        output.closeEntry();
      }
      output.putNextEntry(new JarEntry("closure/b/Unused.class"));
      output.write(unused);
      output.closeEntry();
      output.putNextEntry(new JarEntry("META-INF/versions/" + release + "/closure/a/Extra.class"));
      output.write(duplicate);
      output.closeEntry();
    }
  }

  private record OwnerEntries(byte[] duplicate, byte[] middle) {}
}
