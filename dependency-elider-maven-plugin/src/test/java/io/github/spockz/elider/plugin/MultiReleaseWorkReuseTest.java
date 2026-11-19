// WHY: Verifies MRJAR SourceData and digests propagate from analysis through staging without
// re-hashing.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.test.CompilationFixtureSupport;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Verifies MRJAR source inspection and digest reuse across plugin stages. */
final class MultiReleaseWorkReuseTest extends MavenElisionServiceEffectiveOutputSupport {
  /** Creates the MRJAR reuse test fixture. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  MultiReleaseWorkReuseTest() {
    super();
  }

  @Test
  void reusesMrjarSourceInspectionAndDigestsAcrossAnalysisPlanningAndStaging() throws Exception {
    final Fixture fixture = fixture(false);
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "17");
    writeMultiReleaseInput(fixture);
    final Path trace = temporaryDirectory.resolve("runtime.lst");
    Files.writeString(
        trace, "closure/a/Entry\nclosure/b/Middle\nclosure/c/Leaf\nclosure/d/Ancestor\n");
    final ServiceOperation operation =
        operation(fixture, trace, null, true, List.of(), "vertical-shading");
    final Path normalizedSource = fixture.snapshot("a").filePath().toAbsolutePath().normalize();
    final java.util.concurrent.atomic.AtomicInteger analysisInspections =
        new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicInteger analysisDigestReads =
        new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicInteger analysisTargetProjections =
        new java.util.concurrent.atomic.AtomicInteger();
    final ElisionAnalysisModel.EffectiveAnalysis effective;
    try (MultiReleaseWorkObserver.Scope ignored =
        MultiReleaseWorkObserver.listen(
            new MultiReleaseWorkObserver.Listener() {
              @Override
              public void onSourceInspected(final Path source) {
                if (normalizedSource.equals(source)) {
                  analysisInspections.incrementAndGet();
                }
              }

              @Override
              public void onDigestRead(final Path source) {
                if (normalizedSource.equals(source)) {
                  analysisDigestReads.incrementAndGet();
                }
              }

              @Override
              public void onProjectionCreated(final Path source, final int release) {
                if (normalizedSource.equals(source) && release == 17) {
                  analysisTargetProjections.incrementAndGet();
                }
              }
            })) {
      effective = operation.service().finishAnalysis(operation.prepared());
    }

    final java.util.concurrent.atomic.AtomicInteger trimInspections =
        new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicInteger trimDigestReads =
        new java.util.concurrent.atomic.AtomicInteger();
    final java.util.concurrent.atomic.AtomicInteger trimProjections =
        new java.util.concurrent.atomic.AtomicInteger();
    final TrimResult result;
    try (MultiReleaseWorkObserver.Scope ignored =
        MultiReleaseWorkObserver.listen(
            new MultiReleaseWorkObserver.Listener() {
              @Override
              public void onSourceInspected(final Path source) {
                if (normalizedSource.equals(source)) {
                  trimInspections.incrementAndGet();
                }
              }

              @Override
              public void onDigestRead(final Path source) {
                if (normalizedSource.equals(source)) {
                  trimDigestReads.incrementAndGet();
                }
              }

              @Override
              public void onProjectionCreated(final Path source, final int release) {
                if (normalizedSource.equals(source)) {
                  trimProjections.incrementAndGet();
                }
              }
            })) {
      result = MavenDependencyTrimmer.trimEffectiveOutputs(effective);
    }

    final MultiReleaseArchivePlan.SourceData sharedSource =
        effective.trimAnalysis().multiReleaseSources().get(normalizedSource);
    final ArtifactTrimRecord record =
        EffectiveOutputCacheTestFiles.record(result.records(), fixture.coordinate("a"));
    final boolean elevatedEntryPresent;
    final boolean unusedRemoved;
    try (JarFile outputJar = new JarFile(record.trimmedPath().toFile())) {
      elevatedEntryPresent = outputJar.getEntry("closure/a/Entry.class") != null;
      unusedRemoved = outputJar.getEntry("closure/a/VersionOnly.class") == null;
    }

    Assertions.assertAll(
        "MRJAR SourceData, digests, and target projection are reused from analysis through staging",
        () ->
            Assertions.assertNotNull(
                sharedSource, "analysis should retain inspected MRJAR SourceData"),
        () ->
            Assertions.assertTrue(
                analysisInspections.get() >= 1,
                "analysis should inspect the MRJAR source at least once"),
        () ->
            Assertions.assertEquals(
                0,
                analysisDigestReads.get(),
                "analysis should capture digests via inspectSource without extra reads"),
        () ->
            Assertions.assertEquals(
                analysisInspections.get(),
                analysisTargetProjections.get(),
                "each analysis pass should build the target-release projection once"),
        () ->
            Assertions.assertEquals(
                0,
                trimInspections.get(),
                "planning and staging should reuse shared SourceData without re-inspecting"),
        () ->
            Assertions.assertEquals(
                0,
                trimDigestReads.get(),
                "fingerprinting and staging should reuse shared digests without re-reading"),
        () ->
            Assertions.assertEquals(
                0,
                trimProjections.get(),
                "planning and staging should not recreate target projections"),
        () ->
            Assertions.assertEquals(
                "elevated_and_trimmed",
                record.mrjarStatus(),
                "MRJAR should be elevated and trimmed"),
        () ->
            Assertions.assertEquals(
                sharedSource.digests().sha256(),
                record.originalSha256(),
                "published provenance should reuse shared SourceData SHA-256"),
        () -> Assertions.assertTrue(elevatedEntryPresent, "elevated Entry.class should be kept"),
        () -> Assertions.assertTrue(unusedRemoved, "unreferenced VersionOnly should be trimmed"));
  }

  private void writeMultiReleaseInput(final Fixture fixture) throws IOException {
    final Path source = fixture.snapshot("a").filePath();
    final Path versionedJar = temporaryDirectory.resolve("versioned-a-reuse.jar");
    CompilationFixtureSupport.compileToJar(
        versionedJar,
        temporaryDirectory.resolve("versioned-a-reuse-src"),
        Map.of(
            "Entry.java",
            "package closure.a; public class Entry { public Object make() { "
                + "return new closure.d.Ancestor(); } }",
            "VersionOnly.java",
            "package closure.a; class VersionOnly {}"),
        fixture.snapshot("d").filePath(),
        17);
    final Path rewritten = temporaryDirectory.resolve("a-mr-reuse.jar");
    final Manifest manifest;
    try (JarFile input = new JarFile(source.toFile())) {
      manifest = input.getManifest() == null ? new Manifest() : new Manifest(input.getManifest());
      manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
      manifest.getMainAttributes().putValue("Multi-Release", "true");
      try (JarFile versioned = new JarFile(versionedJar.toFile());
          JarOutputStream output =
              new JarOutputStream(Files.newOutputStream(rewritten), manifest)) {
        copyEntries(
            input,
            output,
            "",
            Set.of(
                "META-INF/versions/17/closure/a/Entry.class",
                "META-INF/versions/17/closure/a/VersionOnly.class"));
        copyEntries(versioned, output, "META-INF/versions/17/", Set.of());
      }
    }
    Files.move(rewritten, source, StandardCopyOption.REPLACE_EXISTING);
  }

  private static void copyEntries(
      final JarFile input,
      final JarOutputStream output,
      final String prefix,
      final Set<String> replacedEntries)
      throws IOException {
    for (final JarEntry entry : input.stream().toList()) {
      if (entry.isDirectory()
          || "META-INF/MANIFEST.MF".equalsIgnoreCase(entry.getName())
          || replacedEntries.contains(entry.getName())) {
        continue;
      }
      copyEntry(input, output, prefix, entry);
    }
  }

  private static void copyEntry(
      final JarFile input, final JarOutputStream output, final String prefix, final JarEntry entry)
      throws IOException {
    output.putNextEntry(new JarEntry(prefix + entry.getName()));
    try (InputStream contents = input.getInputStream(entry)) {
      contents.transferTo(output);
    }
    output.closeEntry();
  }
}
