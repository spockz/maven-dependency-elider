/* WHY: Checks Analyze and Elide agree when vertical shading emits an elevated MRJAR. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import org.apache.maven.execution.MavenSession;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Checks zero-prune MRJAR elevation output parity. */
final class RuntimeEvidenceMrjarOutputParityTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ RuntimeEvidenceMrjarOutputParityTest() {
    super();
  }

  @ParameterizedTest
  @ValueSource(ints = {11, 17})
  void analyzePredictionIncludesZeroPruneElevatedMrjarOutputRow(final int targetRelease)
      throws Exception {
    final Fixture fixture = fixtureWithRuntimeA(targetRelease);
    final Path upperClass =
        RuntimeEvidenceArchiveFixture.compileJar(
            temporaryDirectory,
            "elevated-zero-prune-upper.jar",
            Map.of(
                "closure/a/Entry.java",
                "package closure.a; public class Entry { "
                    + "public Object make() { return null; } }"),
            null,
            17);
    final Path elevatedInput =
        RuntimeEvidenceArchiveFixture.mergedJar(
            fixture.snapshot("a").filePath(),
            upperClass,
            temporaryDirectory.resolve("elevated-zero-prune-input.jar"),
            Map.of(),
            "META-INF/versions/17/");
    fixture.artifacts().get(0).setFile(elevatedInput.toFile());
    fixture.mavenProject().setArtifacts(Set.copyOf(fixture.artifacts()));
    fixture
        .mavenProject()
        .getProperties()
        .setProperty("maven.compiler.release", Integer.toString(targetRelease));
    final Set<String> allRoots = RuntimeEvidenceArchiveFixture.classNames(elevatedInput);
    final Path trace = temporaryDirectory.resolve("elevated-zero-prune.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final Path analyzeReport =
        temporaryDirectory.resolve("elevated-zero-prune-analyze-report.json");
    final Path analyzeSummary = temporaryDirectory.resolve("elevated-zero-prune-analyze.json");
    final AnalyzeMojo analyze = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession analyzeSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(analyzeSession, fixture);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.SESSION_FIELD, analyzeSession);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(analyze, "reportFile", analyzeReport.toFile());
    AnalyzeMojoTestFieldSupport.set(analyze, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(analyze, "trimRoots", List.copyOf(allRoots));
    AnalyzeMojoTestFieldSupport.set(
        analyze, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING);
    AnalyzeMojoTestFieldSupport.set(analyze, "analysisSummaryFile", analyzeSummary.toFile());
    analyze.execute();
    final MavenElisionReportSnapshot prediction = MavenElisionReportWriter.read(analyzeSummary);

    final Path elideSummary = temporaryDirectory.resolve("elevated-zero-prune-elide.json");
    final Path elideReport = temporaryDirectory.resolve("elevated-zero-prune-elide-report.json");
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession elideSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(elideSession, fixture);
    AnalyzeMojoTestFieldSupport.set(elide, RuntimeEvidenceGoalFixture.SESSION_FIELD, elideSession);
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(elide, "reportFile", elideReport.toFile());
    AnalyzeMojoTestFieldSupport.set(elide, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(elide, "trimRoots", List.copyOf(allRoots));
    AnalyzeMojoTestFieldSupport.set(
        elide, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING);
    AnalyzeMojoTestFieldSupport.set(elide, "summaryFile", elideSummary.toFile());
    elide.execute();
    final MavenElisionReportSnapshot applied = MavenElisionReportWriter.read(elideSummary);
    final List<MavenElisionReportSnapshot.TrimmedArtifact> predictedRows =
        prediction.trimmedArtifacts().stream()
            .filter(row -> row.coordinate().contains("fixture:a:jar:1.0"))
            .toList();
    final List<MavenElisionReportSnapshot.TrimmedArtifact> appliedRows =
        applied.trimmedArtifacts().stream()
            .filter(row -> row.coordinate().contains("fixture:a:jar:1.0"))
            .toList();
    final Path appliedArchivePath =
        RuntimeEvidenceGoalFixture.artifactPath(fixture.artifacts().get(0));

    assertAll(
        "Analyze predicts the zero-class MRJAR output Elide creates for vertical shading",
        () -> {
          assertThat(predictedRows).hasSize(1);
          final MavenElisionReportSnapshot.TrimmedArtifact predictedRow = predictedRows.getFirst();
          assertAll(
              "Analyze's predicted row describes vertical elevation",
              () ->
                  assertEquals(
                      0,
                      predictedRow.programClassesPruned(),
                      "Vertical shading can emit an elevation-only archive"),
              () -> assertThat(predictedRow.mrjarStatus()).isEqualTo("elevated_and_trimmed"),
              () -> assertThat(predictedRow.serviceDescriptorChanges()).isEmpty());
        },
        () -> {
          assertThat(appliedRows).hasSize(1);
          final MavenElisionReportSnapshot.TrimmedArtifact appliedRow = appliedRows.getFirst();
          assertAll(
              "Elide's applied row describes vertical elevation",
              () ->
                  assertEquals(
                      0,
                      appliedRow.programClassesPruned(),
                      "Elide preserves the elevated archive classes"),
              () -> assertThat(appliedRow.mrjarStatus()).isEqualTo("elevated_and_trimmed"),
              () -> assertThat(appliedRow.serviceDescriptorChanges()).isEmpty());
        },
        () -> {
          try (JarFile output = new JarFile(appliedArchivePath.toFile())) {
            final String retainedEntry =
                targetRelease >= 17
                    ? "closure/a/Entry.class"
                    : "META-INF/versions/17/closure/a/Entry.class";
            assertAll(
                "Elide physically writes the elevated MRJAR",
                () -> assertThat(output.getJarEntry("META-INF/MANIFEST.MF")).isNotNull(),
                () -> assertThat(output.getJarEntry(retainedEntry)).isNotNull());
          }
        });
  }
}
