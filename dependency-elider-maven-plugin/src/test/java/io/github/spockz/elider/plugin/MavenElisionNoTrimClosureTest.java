/* WHY: Proves trim-disabled graph closure scans retained physical bytecode only when required. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Checks trim-disabled graph closure and output behavior. */
final class MavenElisionNoTrimClosureTest extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Rewritten entry used to model an untraced reference. */
  private static final String EXTRA_ENTRY = "closure/a/Extra.class";

  /** Runtime trace root for both closure scenarios. */
  private static final String ENTRY_CLASS = "closure.a.Entry";

  /** Untraced class whose physical reference must be discovered. */
  private static final String MODELED_EXTRA_CLASS = "closure.a.Extra";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* package */ MavenElisionNoTrimClosureTest() {
    super();
  }

  @Test
  void noTrimPromotesRetainedBytecodeClosureWithBoundGraph() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA();
    replaceExtraWithAncestorReference(fixture.snapshot("a").filePath());
    final Path trace = temporaryDirectory.resolve("runtime-no-trim.lst");
    Files.writeString(trace, ENTRY_CLASS.replace('.', '/') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.AnalysisOptions options =
        new ElisionAnalysisModel.AnalysisOptions(
            List.of(trace.toFile()),
            List.of(),
            null,
            null,
            new ElisionAnalysisModel.CompletenessOptions(false, false, false, true),
            new ElisionAnalysisModel.TrimOptions(
                false,
                List.of(),
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new ElisionAnalysisModel.DynamicRootOptions(true));
    final ElisionAnalysisModel.PreparedAnalysis raw =
        service.prepare(fixture.mavenProject(), options);
    final ResolverArtifactGraphCapturePair pair =
        MavenElisionServiceEffectiveAnalysisFixtures.graphPairWithAncestorEdges(fixture, false);
    final EffectiveGraphPolicy.Evaluation evaluation =
        EffectiveGraphPolicy.evaluatePair(pair, raw.rawDecision());
    final MavenElisionGraphBinding.Result binding =
        new MavenElisionGraphBinding.Result(
            evaluation,
            raw.graphBinding().inventoryFingerprint(),
            raw.graphBinding().operationFingerprint(),
            pair);
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        MavenElisionServiceEffectiveAnalysisFixtures.withBinding(raw, binding);
    final ElisionAnalysisModel.EffectiveAnalysis result = service.finishAnalysis(prepared);
    final ElisionAnalysisModel.Analysis completed = service.finishEffectiveOutputs(result);
    final Set<ArtifactCoordinate> retained = result.effectiveDecision().retainedArtifacts();

    assertAll(
        "trim-disabled analysis closes retained bytecode over a bound graph without outputs",
        () -> assertThat(raw.trace().loadedClassesDotFormat()).containsExactly(ENTRY_CLASS),
        () ->
            assertThat(raw.index().classesByArtifact().values())
                .anySatisfy(classes -> assertThat(classes).contains(MODELED_EXTRA_CLASS)),
        () ->
            assertThat(raw.rawDecision().elidedArtifacts())
                .contains(fixture.coordinate("b"), fixture.coordinate("c")),
        () ->
            assertThat(retained)
                .contains(
                    fixture.coordinate("a"),
                    fixture.coordinate("b"),
                    fixture.coordinate("c"),
                    fixture.coordinate("d"),
                    fixture.coordinate("e")),
        () -> assertThat(result.effectiveDecision().elidedArtifacts()).isEmpty(),
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                result.trimAnalysis().analysisRuns() > 0, "bound graph closure should scan bytes"),
        () -> assertThat(completed.trimResult().records()).isEmpty(),
        () -> assertThat(temporaryDirectory.resolve("build/elided-artifacts")).doesNotExist());
  }

  @Test
  void noTrimFailClosedWithoutBanSkipsBytecodeAnalysis() throws Exception {
    final Fixture fixture = fixture(false);
    replaceExtraClass(fixture.snapshot("a").filePath(), new byte[] {0});
    final Path trace = temporaryDirectory.resolve("runtime-fail-closed-no-trim.lst");
    Files.writeString(trace, ENTRY_CLASS.replace('.', '/') + "\n");
    final MavenElisionService service = new MavenElisionService();
    final ElisionAnalysisModel.PreparedAnalysis prepared =
        service.prepare(
            fixture.mavenProject(),
            MavenElisionServiceEffectiveAnalysisFixtures.options(
                List.of(trace.toFile()), null, false));
    final ElisionAnalysisModel.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final ElisionAnalysisModel.Analysis completed = service.finishEffectiveOutputs(effective);

    assertAll(
        "fail-closed trim-disabled analysis avoids parsing unavailable provider bytecode",
        () ->
            org.junit.jupiter.api.Assertions.assertTrue(
                effective.graphEvaluation().failClosed(),
                "missing graph evidence must fail closed"),
        () ->
            org.junit.jupiter.api.Assertions.assertFalse(
                effective.banPlan().requested(),
                "the zero-scan path applies without requested bans"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                0, effective.trimAnalysis().analysisRuns(), "fail-closed fast path avoids parsing"),
        () -> assertThat(effective.trimAnalysis().candidateAnalyses()).isEmpty(),
        () -> assertThat(completed.trimResult().records()).isEmpty());
  }

  private void replaceExtraWithAncestorReference(final Path archivePath) throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "closure/a/Extra", null, "java/lang/Object", null);
    writer
        .visitField(Opcodes.ACC_PUBLIC, "ancestor", "Lclosure/d/Ancestor;", null, null)
        .visitEnd();
    writer.visitEnd();
    replaceExtraClass(archivePath, writer.toByteArray());
  }

  private void replaceExtraClass(final Path archivePath, final byte[] replacement)
      throws IOException {
    final Path staged = temporaryDirectory.resolve("a-with-untraced-link.jar");
    try (JarFile archive = new JarFile(archivePath.toFile());
        ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(staged))) {
      final Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        copyEntry(archive, output, entries.nextElement(), replacement);
      }
    }
    Files.move(staged, archivePath, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
  }

  private static void copyEntry(
      final JarFile archive,
      final ZipOutputStream output,
      final JarEntry entry,
      final byte[] replacement)
      throws IOException {
    output.putNextEntry(new ZipEntry(entry.getName()));
    if (EXTRA_ENTRY.equals(entry.getName())) {
      output.write(replacement);
    } else {
      try (InputStream input = archive.getInputStream(entry)) {
        input.transferTo(output);
      }
    }
    output.closeEntry();
  }
}
