/* WHY: Checks provided modular archives remain outside the transformed candidate set. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarFile;
import org.apache.maven.execution.MavenSession;
import org.junit.jupiter.api.Test;

/** Checks provided modular inputs pass through unchanged. */
final class RuntimeEvidenceProvidedModulePassThroughTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ RuntimeEvidenceProvidedModulePassThroughTest() {
    super();
  }

  @Test
  void classpathOnlyPredictionExcludesProvidedModulePassThrough() throws Exception {
    final Fixture fixture = fixtureWithProvidedA(11);
    final Path modularInput =
        RuntimeEvidenceArchiveFixture.addRootModuleInfo(
            fixture.snapshot("a").filePath(),
            temporaryDirectory.resolve("provided-module-input.jar"));
    fixture.artifacts().get(0).setFile(modularInput.toFile());
    fixture.mavenProject().setArtifacts(Set.copyOf(fixture.artifacts()));
    fixture.mavenProject().getProperties().setProperty("maven.compiler.release", "11");
    final Path trace = temporaryDirectory.resolve("provided-module.lst");
    Files.writeString(trace, "closure/a/Entry\n");

    final Path analyzeSummary = temporaryDirectory.resolve("provided-module-analyze.json");
    final AnalyzeMojo analyze = new AnalyzeMojo();
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
        temporaryDirectory.resolve("provided-module-analyze-report.json").toFile());
    AnalyzeMojoTestFieldSupport.set(analyze, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        analyze, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY);
    AnalyzeMojoTestFieldSupport.set(analyze, "analysisSummaryFile", analyzeSummary.toFile());
    analyze.execute();
    final MavenElisionReportSnapshot prediction = MavenElisionReportWriter.read(analyzeSummary);

    final Path elideSummary = temporaryDirectory.resolve("provided-module-elide.json");
    final ElideMojo elide = new ElideMojo();
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
        temporaryDirectory.resolve("provided-module-elide-report.json").toFile());
    AnalyzeMojoTestFieldSupport.set(elide, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        elide, "mrjarStrategy", MavenDependencyTrimmer.MRJAR_CLASSPATH_ONLY);
    AnalyzeMojoTestFieldSupport.set(elide, "summaryFile", elideSummary.toFile());
    elide.execute();
    final MavenElisionReportSnapshot applied = MavenElisionReportWriter.read(elideSummary);

    assertAll(
        "provided modular inputs remain outside the transformed output candidate set",
        () ->
            assertThat(prediction.trimmedArtifacts())
                .noneMatch(row -> row.coordinate().contains("fixture:a:jar:1.0")),
        () ->
            assertThat(applied.trimmedArtifacts())
                .noneMatch(row -> row.coordinate().contains("fixture:a:jar:1.0")),
        () -> assertThat(fixture.artifacts().get(0).getFile()).isEqualTo(modularInput.toFile()),
        () -> {
          try (JarFile archive = new JarFile(modularInput.toFile())) {
            assertThat(archive.getJarEntry("module-info.class")).isNotNull();
          }
        });
  }
}
