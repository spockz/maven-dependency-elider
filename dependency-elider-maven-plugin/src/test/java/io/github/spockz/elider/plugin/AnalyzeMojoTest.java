// WHY: Ensures analyze rejects missing explicit evidence instead of producing a misleading result.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.plugin.AnalyzeMojoTestArtifactSupport.artifact;
import static io.github.spockz.elider.plugin.AnalyzeMojoTestArtifactSupport.artifactWithClasses;
import static io.github.spockz.elider.plugin.AnalyzeMojoTestArtifactSupport.fixture;
import static io.github.spockz.elider.plugin.AnalyzeMojoTestFieldSupport.seedSelectedBanCapture;
import static io.github.spockz.elider.plugin.AnalyzeMojoTestFieldSupport.set;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.plugin.AnalyzeMojoTestArtifactSupport.Fixture;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies conservative Maven artifact adaptation and explicit trace requirements. */
@SuppressWarnings({"PMD.UnitTestContainsTooManyAsserts", "PMD.LawOfDemeter", "PMD.TooManyMethods"})
final class AnalyzeMojoTest {
  /** WHY: CVE fixtures use one stable vulnerable symbol in mappings and assertions. */
  private static final String UNUSED_CLASS = "unused.Idle";

  /** Temporary directory for ZIP fixtures and explicit trace files. */
  @TempDir private Path tempDir;

  /** Creates the focused test fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  AnalyzeMojoTest() {}

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void analyzesExplicitTraceWithoutMutatingArtifactsAndReportsCompleteInput()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        artifact(tempDir, "used", "1.0", "compile", "jar", "used.jar", "used/Sample.class");
    final Artifact unused =
        artifact(tempDir, "unused", "1.0", "compile", "jar", "unused.jar", "unused/Sample.class");
    final Artifact excluded =
        artifact(
            tempDir, "excluded", "2.0", "runtime", "jar", "excluded.jar", "excluded/Sample.class");
    final Artifact testScoped =
        artifact(tempDir, "test-only", "1.0", "test", "jar", "test.jar", "test/Sample.class");
    final Artifact nonJar =
        new DefaultArtifact(
            "org.example",
            "metadata",
            "1.0",
            "compile",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));
    final File usedFile = used.getFile();
    final File unusedFile = unused.getFile();
    final File excludedFile = excluded.getFile();
    final File testScopedFile = testScoped.getFile();
    final Set<Artifact> artifacts =
        new LinkedHashSet<>(List.of(used, unused, excluded, testScoped, nonJar));
    final Set<Artifact> directArtifacts = new LinkedHashSet<>(Set.of(used, excluded));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(directArtifacts);
    final Set<Artifact> resolvedSnapshot = Set.copyOf(project.getArtifacts());
    final Set<Artifact> directSnapshot = Set.copyOf(project.getDependencyArtifacts());
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, "used/Sample\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "retainedArtifacts", List.of("org.example:excluded"));
    final Path report = tempDir.resolve("analysis.json");
    set(mojo, "reportFile", report.toFile());
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(project.getArtifacts()).isSameAs(artifacts);
    assertThat(project.getArtifacts()).containsExactlyInAnyOrderElementsOf(resolvedSnapshot);
    assertThat(project.getDependencyArtifacts()).isSameAs(directArtifacts);
    assertThat(project.getDependencyArtifacts())
        .containsExactlyInAnyOrderElementsOf(directSnapshot);
    assertThat(used.getFile()).isSameAs(usedFile);
    assertThat(unused.getFile()).isSameAs(unusedFile);
    assertThat(excluded.getFile()).isSameAs(excludedFile);
    assertThat(testScoped.getFile()).isSameAs(testScopedFile);
    assertThat(log.messages())
        .contains(
            "  Artifacts that would be elided by this analysis: 0 / 5 (0.0%)",
            "  Estimated original JAR bytes for those artifacts: 0 B "
                + "(sum of original on-disk input JAR sizes; final package delta may differ)",
            "  JAR trim cache: unavailable (trim stage not run)");
    assertThat(log.messages())
        .noneMatch(
            line ->
                line.startsWith("  Classes removed:")
                    || line.startsWith("  Methods removed:")
                    || line.startsWith("  Fields removed:"));
    final com.fasterxml.jackson.databind.JsonNode json =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(report.toFile());
    assertThat(json.path("staticEvidenceAvailable").asBoolean()).isFalse();
    assertThat(json.path("groups").path("applicationReferenced").isNull()).isTrue();
    assertThat(json.path("groups").path("runtimeObservedWithoutApplicationReference").isNull())
        .isTrue();
    assertThat(json.path("groups").path("neitherReferencedNorObserved").isNull()).isTrue();
    assertThat(json.path("runtimeObservedClasses").toString()).contains("used.Sample");
    assertThat(json.path("classes").toString()).contains("UNKNOWN_STATIC_EVIDENCE");
  }

  @Test
  void reportsPredictedElisionsAndExactOriginalJarBytesWithoutMutation()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        artifact(
            tempDir, "used", "1.0", "compile", "jar", "analysis-used.jar", "used/Sample.class");
    final Artifact unused =
        artifact(
            tempDir,
            "unused-runtime",
            "1.0",
            "runtime",
            "jar",
            "analysis-unused.jar",
            "unused/Idle.class");
    final File unusedFile = unused.getFile();
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(used, unused));
    final MavenProject project = new MavenProject();
    project.setArtifacts(artifacts);
    final Path trace = tempDir.resolve("predicted-elisions.lst");
    Files.writeString(trace, "used/Sample\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "reportFile", tempDir.resolve("predicted-elisions.json").toFile());
    set(mojo, "cveCacheDirectory", tempDir.resolve("analysis-cve-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19001");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("unused-runtime");
    mapping.setVersion("1.0");
    mapping.setVulnerableClasses(List.of(UNUSED_CLASS));
    set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(log.messages())
        .contains(
            "  Artifacts that would be elided by this analysis: 1 / 2 (50.0%)",
            "  Estimated original JAR bytes for those artifacts: "
                + MavenElisionReportWriter.formatBytes(Files.size(unused.getFile().toPath()))
                + " (sum of original on-disk input JAR sizes; final package delta may differ)",
            "  Advisories associated with components that would be removed: "
                + "none verified by published trim evidence",
            "  Mitigated CVEs (vulnerable code that would be pruned by trimming): "
                + "no published omission proof",
            "  CVEs that would be inactive due to unmet prerequisite dependencies: "
                + "no precondition proof available",
            "  Vulnerability mappings that remain unverified by the in-memory Analyze prediction:",
            "    CVE-2026-19001 org.example:unused-runtime:jar:1.0");
    assertThat(project.getArtifacts()).isSameAs(artifacts).containsExactlyInAnyOrder(used, unused);
    assertThat(unused.getFile()).isSameAs(unusedFile);
    assertThat(log.messages())
        .noneMatch(
            line ->
                line.startsWith("  Classes removed:")
                    || line.startsWith("  Methods removed:")
                    || line.startsWith("  Fields removed:"));
  }

  @Test
  void doesNotClaimTrimmedCodeProofWithoutPublishedTrimEvidence()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact runtime = artifactWithClasses(tempDir, "runtime-cve", "runtime-cve.jar");
    final File original = runtime.getFile();
    final MavenProject project = new MavenProject();
    project.setArtifacts(new LinkedHashSet<>(List.of(runtime)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("trim-analysis-target").toString());
    project.setBuild(build);
    final Path trace = tempDir.resolve("trim-analysis.lst");
    Files.writeString(trace, "sample.Keep\n");
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", project);
    set(mojo, "traceFiles", List.of(trace.toFile()));
    set(mojo, "trimJars", true);
    set(mojo, "reportFile", tempDir.resolve("trim-analysis.json").toFile());
    set(mojo, "cveCacheDirectory", tempDir.resolve("trim-analysis-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19002");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("runtime-cve");
    mapping.setVersion("1.0");
    mapping.setVulnerableClasses(List.of("sample.Drop"));
    set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(log.messages())
        .contains(
            "  Vulnerability mappings that remain unverified by the in-memory Analyze prediction:",
            "    CVE-2026-19002 org.example:runtime-cve:jar:1.0")
        .noneMatch(
            line ->
                line.startsWith(
                        "  Mitigated CVEs (vulnerable code that would be pruned by trimming):")
                    && line.contains("CVE-2026-19002"));
    assertThat(project.getArtifacts()).containsExactly(runtime);
    assertThat(runtime.getFile()).isSameAs(original);
    assertThat(TrimPaths.cacheManifestPath(project)).doesNotExist();
    assertThat(TrimPaths.generationPath(project, "prediction-only")).doesNotExist();
  }

  @Test
  void rejectsInvalidRetentionCoordinates() throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture(tempDir, "used/Sample\n");
    set(fixture.mojo(), "retainedArtifacts", List.of("org.example"));

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Invalid elide.retainedArtifacts coordinate");
  }

  @Test
  void banRequestFailsClosedWithoutPublishingReport()
      throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture(tempDir, "used/Sample\n");
    final Path report = tempDir.resolve("ban-guard-report.json");
    final String previousReport = "previous report";
    Files.writeString(report, previousReport);
    set(fixture.mojo(), "banishedDependencies", List.of("org.example:used"));
    set(fixture.mojo(), "reportFile", report.toFile());
    set(
        fixture.mojo(),
        "predictionService",
        (AnalyzePredictionService)
            (project, options, resolver) -> {
              throw new MojoFailureException("prediction service was called before ban rejection");
            });
    fixture.project().setFile(tempDir.resolve("ban-consumer-pom.xml").toFile());
    seedSelectedBanCapture(fixture.mojo(), fixture.project(), List.of("org.example:used"));

    assertAll(
        "analyze rejects ban requests before publishing a report",
        () ->
            assertThatThrownBy(fixture.mojo()::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining(
                    "cannot be applied because strict ban enforcement is not available"),
        () -> assertThat(Files.readString(report)).isEqualTo(previousReport));
  }

  @Test
  void rejectsTraceObservationsThatMatchNoDependency()
      throws IOException, ReflectiveOperationException {
    final Fixture fixture = fixture(tempDir, "missing/Sample\n");

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
  }

  @Test
  void rejectsAnEmptyTraceList() throws ReflectiveOperationException {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    set(mojo, "project", new MavenProject());
    set(mojo, "traceFiles", List.of());

    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("At least one supported trace input is required");
  }

  @Test
  void retainsUnsupportedTypesWithoutFile() throws IOException {
    final Artifact pom =
        new DefaultArtifact(
            "org.example",
            "metadata",
            "1.0",
            "compile",
            "pom",
            null,
            new DefaultArtifactHandler("pom"));

    assertThat(MavenArtifactInventory.isJarCandidate(pom)).isFalse();
  }

  @Test
  void rejectsMissingResolvedArtifactFiles() {
    final Artifact jar =
        new DefaultArtifact(
            "org.example",
            "library",
            "1.0",
            "compile",
            "jar",
            null,
            new DefaultArtifactHandler("jar"));

    assertThatThrownBy(() -> MavenArtifactInventory.isJarCandidate(jar))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Resolved artifact has no regular file");
  }

  @Test
  @DisplayName("ADR-0011: leafOnly skips intermediate module in AnalyzeMojo")
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void leafOnlySkipsIntermediateReactorModule() throws Exception {
    final AnalyzeMojo mojo = new AnalyzeMojo();
    final MavenProject intermediate = new MavenProject();
    intermediate.setGroupId("io.github.spockz.test");
    intermediate.setArtifactId("intermediate-core");
    intermediate.setVersion("1.0.0");
    intermediate.setPackaging("jar");

    final MavenProject leaf = new MavenProject();
    leaf.setGroupId("io.github.spockz.test");
    leaf.setArtifactId("leaf-app");
    leaf.setVersion("1.0.0");
    leaf.setPackaging("jar");

    final MavenSession session =
        ReactorLeafModuleDetectorTest.createSession(
            new ReactorLeafModuleDetectorTest.StubProjectDependencyGraph(
                List.of(intermediate, leaf), Map.of(intermediate, List.of(leaf))));

    set(mojo, "project", intermediate);
    set(mojo, "session", session);
    final Path report = tempDir.resolve("intermediate-ban-report.json");
    Files.writeString(report, "existing report");
    set(mojo, "reportFile", report.toFile());
    set(mojo, "banishedDependencies", List.of("org.example:library"));
    // leafOnly is true by default: skips without failing on missing trace files
    assertAll(
        "leafOnly Analyze skips before requiring a ban capture or publishing a report",
        () -> assertThatCode(mojo::execute).doesNotThrowAnyException(),
        () -> assertThat(Files.readString(report)).isEqualTo("existing report"));
  }
}
