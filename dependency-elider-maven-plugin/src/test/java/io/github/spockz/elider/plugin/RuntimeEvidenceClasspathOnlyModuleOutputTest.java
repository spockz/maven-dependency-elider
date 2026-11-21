/* WHY: Checks Analyze and Elide agree on classpath-only module descriptor removal. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.junit.jupiter.api.Test;

/** Checks classpath-only module output parity. */
final class RuntimeEvidenceClasspathOnlyModuleOutputTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ RuntimeEvidenceClasspathOnlyModuleOutputTest() {
    super();
  }

  @Test
  void analyzePredictionMatchesClasspathOnlyModuleOutputStatus() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA(11);
    final Path modularInput =
        RuntimeEvidenceArchiveFixture.addRootModuleInfo(
            fixture.snapshot("a").filePath(),
            temporaryDirectory.resolve("classpath-only-module-input.jar"));
    fixture.artifacts().get(0).setFile(modularInput.toFile());
    fixture.mavenProject().setArtifacts(Set.copyOf(fixture.artifacts()));
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "11");
    final Path trace = temporaryDirectory.resolve("classpath-only-module.lst");
    Files.writeString(trace, "closure/a/Entry\n");
    final Path analyzeSummary = temporaryDirectory.resolve("classpath-only-module-analyze.json");
    final AnalyzeMojo analyze = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession analyzeSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(analyzeSession, fixture);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.SESSION_FIELD, analyzeSession);
    AnalyzeMojoTestFieldSupport.set(
        analyze, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(
        analyze,
        "reportFile",
        temporaryDirectory.resolve("classpath-only-module-analyze-report.json").toFile());
    AnalyzeMojoTestFieldSupport.set(analyze, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        analyze, "trimRoots", List.of("closure.a.Entry", "closure.a.Extra"));
    AnalyzeMojoTestFieldSupport.set(
        analyze, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY);
    AnalyzeMojoTestFieldSupport.set(analyze, "analysisSummaryFile", analyzeSummary.toFile());
    analyze.execute();
    final MavenElisionReportSnapshot prediction = MavenElisionReportWriter.read(analyzeSummary);

    final Path elideSummary = temporaryDirectory.resolve("classpath-only-module-elide.json");
    final ElideMojo elide = ExplicitRuntimeMojoTestSupport.newElideMojo();
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.PROJECT_FIELD, fixture.mavenProject());
    final MavenSession elideSession = RuntimeEvidenceGoalFixture.session(fixture.mavenProject());
    RuntimeEvidenceGoalFixture.seedCapturedGraph(elideSession, fixture);
    AnalyzeMojoTestFieldSupport.set(elide, RuntimeEvidenceGoalFixture.SESSION_FIELD, elideSession);
    AnalyzeMojoTestFieldSupport.set(
        elide, RuntimeEvidenceGoalFixture.TRACE_FILES_FIELD, List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(
        elide,
        "reportFile",
        temporaryDirectory.resolve("classpath-only-module-elide-report.json").toFile());
    AnalyzeMojoTestFieldSupport.set(elide, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        elide, "trimRoots", List.of("closure.a.Entry", "closure.a.Extra"));
    AnalyzeMojoTestFieldSupport.set(
        elide, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY);
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
    final Artifact artifact = fixture.artifacts().get(0);
    final Path output = RuntimeEvidenceGoalFixture.artifactPath(artifact);

    assertAll(
        "Analyze and Elide report the classpath-only module transformation consistently",
        () -> {
          assertThat(predictedRows).hasSize(1);
          final MavenElisionReportSnapshot.TrimmedArtifact predictedRow = predictedRows.getFirst();
          assertAll(
              "Analyze predicts module removal without class pruning",
              () ->
                  assertEquals(
                      0,
                      predictedRow.programClassesPruned(),
                      "Module removal does not prune classes"),
              () -> assertThat(predictedRow.mrjarStatus()).isEqualTo("classpath-only"),
              () -> assertThat(predictedRow.serviceDescriptorChanges()).isEmpty());
        },
        () -> {
          assertThat(appliedRows).hasSize(1);
          final MavenElisionReportSnapshot.TrimmedArtifact appliedRow = appliedRows.getFirst();
          assertAll(
              "Elide reports the same classpath-only result",
              () ->
                  assertEquals(
                      0,
                      appliedRow.programClassesPruned(),
                      "Elide preserves all application classes"),
              () -> assertThat(appliedRow.mrjarStatus()).isEqualTo("classpath-only"),
              () -> assertThat(appliedRow.serviceDescriptorChanges()).isEmpty());
        },
        () -> {
          try (JarFile archive = new JarFile(output.toFile())) {
            assertAll(
                "Classpath-only output strips the module descriptor and preserves program classes",
                () -> assertThat(archive.getJarEntry("module-info.class")).isNull(),
                () -> assertThat(archive.getJarEntry("closure/a/Entry.class")).isNotNull(),
                () -> assertThat(archive.getJarEntry("closure/a/Extra.class")).isNotNull());
          }
        });
  }
}
