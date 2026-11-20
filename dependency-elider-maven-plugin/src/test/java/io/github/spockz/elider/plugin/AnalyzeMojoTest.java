// WHY: Ensures Analyze rejects missing evidence instead of misleading users.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Tests Analyze inputs. JUnit uses its implicit constructor. */
@SuppressWarnings({
  "PMD.LawOfDemeter",
  "PMD.CommentRequired",
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods"
})
final class AnalyzeMojoTest {
  private static final String PROJECT_FIELD = "project";
  private static final String REPORT_FILE_FIELD = "reportFile";
  private static final String SUMMARY_FILE_FIELD = "analysisSummaryFile";
  private static final String TRACE_CLASS_USAGE = "used/Sample\n";

  /** CVE fixtures share one vulnerable symbol. */
  private static final String UNUSED_CLASS = "unused.Idle";

  /** Temporary directory for ZIP fixtures and explicit trace files. */
  @TempDir private Path tempDir;

  private static MojoExecution lifecycleExecution(final Plugin plugin, final String phase)
      throws ReflectiveOperationException {
    final MojoExecution execution = new MojoExecution(plugin, "analyze", phase + "-binding");
    execution.setLifecyclePhase(phase);
    AnalyzeMojoTestFieldSupport.set(execution, "source", MojoExecution.Source.LIFECYCLE);
    return execution;
  }

  @Test
  void trustsApplicationOutputOnlyWhenAnalyzeRunsAtProcessClassesBinding()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, TRACE_CLASS_USAGE);
    final AnalyzeMojo mojo = fixture.mojo();
    final MavenProject project = fixture.project();
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of("clean", "process-classes"));
    final MavenSession session = new MavenSession(null, request, null, project);
    AnalyzeMojoTestFieldSupport.set(mojo, "session", session);
    final List<Boolean> trustedContexts = new java.util.ArrayList<>();
    AnalyzeMojoTestFieldSupport.set(
        mojo,
        "predictionService",
        (AnalyzePredictionService)
            (currentProject, options, resolver) -> {
              trustedContexts.add(options.completeness().trustedProcessClassesContext());
              final ElisionAnalysisModel.AnalysisEvidence evidence =
                  new ElisionAnalysisModel.AnalysisEvidence(
                      new io.github.spockz.elider.engine.ClassUsageReport(List.of()),
                      Optional.empty(),
                      Map.of(),
                      false,
                      options.completeness().trustedProcessClassesContext(),
                      null,
                      Set.of());
              return new AnalyzePrediction(
                  MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
                  List.of(),
                  List.of(),
                  List.of(),
                  List.of(),
                  evidence,
                  "a".repeat(64),
                  "b".repeat(64),
                  "c".repeat(64));
            });
    final Plugin plugin = new Plugin();
    for (final String phase : List.of("initialize", "process-classes")) {
      AnalyzeMojoTestFieldSupport.set(mojo, "mojoExecution", lifecycleExecution(plugin, phase));
      mojo.execute();
    }

    assertAll(
        "requested later lifecycle goals do not prove the current execution reached that phase",
        () -> assertThat(trustedContexts).containsExactly(false, true));
  }

  @Test
  void sourceRootsCompleteFailsBeforeAnalysisWithMigrationGuidance() throws Exception {
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "early-rejection");
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    final AtomicBoolean analysisStarted = new AtomicBoolean();
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.set(mojo, "sourceRootsComplete", true);
    AnalyzeMojoTestFieldSupport.set(
        mojo,
        "predictionService",
        (AnalyzePredictionService)
            (currentProject, options, resolver) -> {
              analysisStarted.set(true);
              return null;
            });

    final Throwable failure = Assertions.catchThrowable(mojo::execute);
    assertAll(
        "obsolete source completeness fails before prediction",
        () ->
            assertThat(failure)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("elide.sourceRootsComplete is no longer supported")
                .hasMessageContaining("bind elide to process-classes"),
        () -> assertThat(analysisStarted).isFalse());
  }

  @Test
  void overlappingReportTargetsFailBeforeEitherOutputIsReplaced() throws Exception {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, "used.Sample\n");
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(fixture.mojo());
    final Path shared = tempDir.resolve("shared-analysis-output.json");
    final byte[] prior = "prior output".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Files.write(shared, prior);
    AnalyzeMojoTestFieldSupport.set(fixture.mojo(), REPORT_FILE_FIELD, shared.toFile());
    AnalyzeMojoTestFieldSupport.set(
        fixture.mojo(),
        SUMMARY_FILE_FIELD,
        shared.getParent().resolve(".").resolve(shared.getFileName()).toFile());

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Duplicate output target path");
    assertThat(Files.readAllBytes(shared)).isEqualTo(prior);
  }

  @Test
  void ancestorAndDescendantReportTargetsFailBeforeEitherOutputIsReplaced() throws Exception {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, "used.Sample\n");
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(fixture.mojo());
    final Path parentTarget = tempDir.resolve("overlapping-output");
    final byte[] prior = "prior output".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Files.write(parentTarget, prior);
    AnalyzeMojoTestFieldSupport.set(fixture.mojo(), REPORT_FILE_FIELD, parentTarget.toFile());
    AnalyzeMojoTestFieldSupport.set(
        fixture.mojo(), SUMMARY_FILE_FIELD, parentTarget.resolve("summary.json").toFile());

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Overlapping output target paths");
    assertThat(Files.readAllBytes(parentTarget)).isEqualTo(prior);
  }

  @Test
  @SuppressWarnings("PMD.AvoidDuplicateLiterals")
  void analyzesExplicitTraceWithoutMutatingArtifactsAndReportsCompleteInput()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "used", "1.0", "compile", "jar", "used.jar", "used/Sample.class");
    final Artifact unused =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "unused", "1.0", "compile", "jar", "unused.jar", "unused/Sample.class");
    final Artifact excluded =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "excluded", "2.0", "runtime", "jar", "excluded.jar", "excluded/Sample.class");
    final Artifact testScoped =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "test-only", "1.0", "test", "jar", "test.jar", "test/Sample.class");
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
    final MavenProject project =
        AnalyzeMojoTestArtifactSupport.project(tempDir, "analysis-summary");
    project.setArtifacts(artifacts);
    project.setDependencyArtifacts(directArtifacts);
    final Set<Artifact> resolvedSnapshot = Set.copyOf(project.getArtifacts());
    final Set<Artifact> directSnapshot = Set.copyOf(project.getDependencyArtifacts());
    final Path trace = tempDir.resolve("runtime.lst");
    Files.writeString(trace, TRACE_CLASS_USAGE);
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "retainedArtifacts", List.of("org.example:excluded"));
    final Path report = tempDir.resolve("analysis.json");
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FILE_FIELD, report.toFile());
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
        .contains("Whole artifacts that would be dropped: 0 / 5 (original JAR file bytes: 0 B)");
    assertThat(log.messages())
        .anyMatch(line -> line.startsWith("Snapshot: analysis prediction at "));
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
    assertThat(json.path("exclusionReview").path("available").booleanValue()).isFalse();
    assertThat(json.path("exclusionReview").path("unavailableReason").textValue())
        .contains("pre-injection");
  }

  @Test
  void writesFrozenRepeatedExclusionsToAnalyzeReport() throws Exception {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, TRACE_CLASS_USAGE);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(fixture.mojo());
    final MavenProject project = fixture.project();
    project.setFile(tempDir.resolve("pom.xml").toFile());
    project.setGroupId("example");
    project.setArtifactId("consumer");
    project.setVersion("1");
    final org.apache.maven.model.Dependency first = new org.apache.maven.model.Dependency();
    first.setGroupId("libs");
    first.setArtifactId("first");
    first.setVersion("1");
    final org.apache.maven.model.Dependency second = first.clone();
    second.setArtifactId("second");
    final org.apache.maven.model.Exclusion exclusion = new org.apache.maven.model.Exclusion();
    exclusion.setGroupId("excluded");
    exclusion.setArtifactId("library");
    first.addExclusion(exclusion);
    second.addExclusion(exclusion.clone());
    project.setDependencies(List.of(first, second));
    AnalyzeMojoTestFieldSupport.seedSelectedBanCapture(fixture.mojo(), project, List.of());
    fixture.mojo().execute();
    final com.fasterxml.jackson.databind.JsonNode report =
        new com.fasterxml.jackson.databind.ObjectMapper()
            .readTree(tempDir.resolve("fixture-report.json").toFile());
    assertAll(
        () -> assertThat(report.path("exclusionReview").path("available").booleanValue()).isTrue(),
        () ->
            assertThat(
                    report
                        .path("exclusionReview")
                        .path("candidates")
                        .get(0)
                        .path("count")
                        .intValue())
                .isEqualTo(2),
        () ->
            assertThat(
                    report
                        .path("exclusionReview")
                        .path("candidates")
                        .get(0)
                        .path("coordinate")
                        .path("groupId")
                        .textValue())
                .isEqualTo("excluded"));
  }

  @Test
  void reportsPredictedElisionsAndExactOriginalJarBytesWithoutMutation()
      throws IOException, ReflectiveOperationException, MojoFailureException {
    final Artifact used =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir, "used", "1.0", "compile", "jar", "analysis-used.jar", "used/Sample.class");
    final Artifact unused =
        AnalyzeMojoTestArtifactSupport.artifact(
            tempDir,
            "unused-runtime",
            "1.0",
            "runtime",
            "jar",
            "analysis-unused.jar",
            "unused/Idle.class");
    final File unusedFile = unused.getFile();
    final Set<Artifact> artifacts = new LinkedHashSet<>(List.of(used, unused));
    final MavenProject project =
        AnalyzeMojoTestArtifactSupport.project(tempDir, "predicted-elisions");
    project.setArtifacts(artifacts);
    final Path trace = tempDir.resolve("predicted-elisions.lst");
    Files.writeString(trace, TRACE_CLASS_USAGE);
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    final Path report = tempDir.resolve("predicted-elisions.json");
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FILE_FIELD, report.toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("analysis-cve-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19001");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("unused-runtime");
    mapping.setVersion("1.0");
    mapping.setAssertsAffected(true);
    mapping.setVulnerableClasses(List.of(UNUSED_CLASS));
    AnalyzeMojoTestFieldSupport.set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertThat(log.messages())
        .contains(
            "Whole artifacts that would be dropped: 0 / 2 (original JAR file bytes: 0 B)",
            "Raw trace decision drops before graph safety: 1",
            "Analysis only: no trim proof or published changes",
            "Vulnerability findings: 1");
    assertAll(
        "the fail-closed graph retains the raw drop without a trim proof",
        () ->
            assertThat(log.messages())
                .anyMatch(
                    line ->
                        line.contains("CVE-2026-19001 org.example:unused-runtime:jar:1.0")
                            && line.contains("[RETAINED_UNCHANGED]")),
        () ->
            assertThat(log.messages())
                .anyMatch(line -> line.contains("Applicability: AFFECTED; intent: AUTO_VERIFY")),
        () -> assertThat(log.messages()).contains("CVE Sources:"),
        () ->
            assertThat(
                    new com.fasterxml.jackson.databind.ObjectMapper()
                        .readTree(report.toFile())
                        .path("dependencyPrediction")
                        .path("wouldElideArtifacts"))
                .isEmpty(),
        () ->
            assertThat(
                    new com.fasterxml.jackson.databind.ObjectMapper()
                        .readTree(report.toFile())
                        .path("dependencyPrediction")
                        .path("plannedClassRemovals"))
                .isEmpty());
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
    final Artifact runtime =
        AnalyzeMojoTestArtifactSupport.artifactWithClasses(
            tempDir, "runtime-cve", "runtime-cve.jar");
    final File original = runtime.getFile();
    final MavenProject project = AnalyzeMojoTestArtifactSupport.project(tempDir, "trim-analysis");
    project.setArtifacts(new LinkedHashSet<>(List.of(runtime)));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("trim-analysis-target").toString());
    project.setBuild(build);
    final Path trace = tempDir.resolve("trim-analysis.lst");
    Files.writeString(trace, "sample.Keep\n");
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, project);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of(trace.toFile()));
    AnalyzeMojoTestFieldSupport.set(mojo, "trimJars", true);
    AnalyzeMojoTestFieldSupport.set(
        mojo, REPORT_FILE_FIELD, tempDir.resolve("trim-analysis.json").toFile());
    AnalyzeMojoTestFieldSupport.set(
        mojo, "cveCacheDirectory", tempDir.resolve("trim-analysis-cache").toFile());
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-19002");
    mapping.setGroupId("org.example");
    mapping.setArtifactId("runtime-cve");
    mapping.setVersion("1.0");
    mapping.setAssertsAffected(true);
    mapping.setVulnerableClasses(List.of("sample.Drop"));
    AnalyzeMojoTestFieldSupport.set(mojo, "vulnerabilityMappings", List.of(mapping));
    final RecordingMavenLog log = new RecordingMavenLog();
    mojo.setLog(log);

    mojo.execute();

    assertAll(
        "unpublished Analyze results retain the finding without declaring omission proof",
        () ->
            assertThat(log.messages())
                .contains("Analysis only: no trim proof or published changes"),
        () -> assertThat(log.messages()).contains("Vulnerability findings: 1"),
        () ->
            assertThat(log.messages())
                .anyMatch(
                    line ->
                        line.contains("CVE-2026-19002 org.example:runtime-cve:jar:1.0")
                            && line.contains("[RETAINED_UNCHANGED]")),
        () ->
            assertThat(log.messages())
                .anyMatch(line -> line.contains("Applicability: AFFECTED; intent: AUTO_VERIFY")),
        () -> assertThat(log.messages()).anyMatch(line -> line.contains("Outcome: NO_PROOF;")),
        () ->
            assertThat(log.messages())
                .noneMatch(
                    line ->
                        line.contains("CVE-2026-19002")
                            && line.contains("Outcome: DECLARED_CODE_ABSENT;")),
        () -> assertThat(log.messages()).anyMatch(line -> line.contains("CACHE UNAVAILABLE")));
    assertThat(project.getArtifacts()).containsExactly(runtime);
    assertThat(runtime.getFile()).isSameAs(original);
    assertThat(TrimPaths.cacheManifestPath(project)).doesNotExist();
    assertThat(TrimPaths.generationPath(project, "prediction-only")).doesNotExist();
  }

  @Test
  void rejectsInvalidRetentionCoordinates() throws IOException, ReflectiveOperationException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, TRACE_CLASS_USAGE);
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(fixture.mojo());
    AnalyzeMojoTestFieldSupport.set(fixture.mojo(), "retainedArtifacts", List.of("org.example"));

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("Invalid elide.retainedArtifacts coordinate");
  }

  @Test
  void selectedBanCaptureWithoutHookFailsClosedWithoutPublishingReport()
      throws IOException, ReflectiveOperationException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, TRACE_CLASS_USAGE);
    final Path report = tempDir.resolve("ban-guard-report.json");
    final String previousReport = "previous report";
    Files.writeString(report, previousReport);
    AnalyzeMojoTestFieldSupport.set(
        fixture.mojo(), "banishedDependencies", List.of("org.example:used"));
    AnalyzeMojoTestFieldSupport.set(fixture.mojo(), REPORT_FILE_FIELD, report.toFile());
    AnalyzeMojoTestFieldSupport.set(
        fixture.mojo(),
        "predictionService",
        (AnalyzePredictionService)
            (project, options, resolver) -> {
              throw new MojoFailureException("prediction service was called before ban rejection");
            });
    fixture.project().setFile(tempDir.resolve("ban-consumer-pom.xml").toFile());
    AnalyzeMojoTestFieldSupport.seedSelectedBanCapture(
        fixture.mojo(), fixture.project(), List.of("org.example:used"));

    assertAll(
        "analyze rejects a selected capture without its lifecycle hook before publishing",
        () ->
            assertThatThrownBy(fixture.mojo()::execute)
                .isInstanceOf(MojoFailureException.class)
                .hasMessageContaining("cannot ignore selected ban capture"),
        () -> assertThat(Files.readString(report)).isEqualTo(previousReport));
  }

  @Test
  void rejectsTraceObservationsThatMatchNoDependency()
      throws IOException, ReflectiveOperationException {
    final AnalyzeMojoTestArtifactSupport.Fixture fixture =
        AnalyzeMojoTestArtifactSupport.fixture(tempDir, "missing/Sample\n");
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(fixture.mojo());

    assertThatThrownBy(fixture.mojo()::execute)
        .isInstanceOf(MojoFailureException.class)
        .hasMessageContaining("no observed class matches any supplied dependency");
  }

  @Test
  void rejectsAnEmptyTraceList() throws ReflectiveOperationException {
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    AnalyzeMojoTestFieldSupport.set(
        mojo, PROJECT_FIELD, AnalyzeMojoTestArtifactSupport.project(tempDir, "skipped-analysis"));
    AnalyzeMojoTestFieldSupport.installLegacyPredictionFixture(mojo);
    AnalyzeMojoTestFieldSupport.set(mojo, "traceFiles", List.of());

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
  void leafOnlySkipsIntermediateReactorModule() throws Exception {
    final AnalyzeMojo mojo = ExplicitRuntimeMojoTestSupport.newAnalyzeMojo();
    final MavenProject intermediate =
        AnalyzeMojoTestArtifactSupport.project(tempDir, "intermediate-core");
    intermediate.setGroupId("io.github.spockz.test");
    intermediate.setArtifactId("intermediate-core");
    intermediate.setVersion("1.0.0");
    intermediate.setPackaging("jar");

    final MavenProject leaf = AnalyzeMojoTestArtifactSupport.project(tempDir, "reactor-leaf");
    leaf.setGroupId("io.github.spockz.test");
    leaf.setArtifactId("leaf-app");
    leaf.setVersion("1.0.0");
    leaf.setPackaging("jar");

    final MavenSession session =
        ReactorLeafModuleDetectorTest.createSession(
            new ReactorLeafModuleDetectorTest.StubProjectDependencyGraph(
                List.of(intermediate, leaf), Map.of(intermediate, List.of(leaf))));

    AnalyzeMojoTestFieldSupport.set(mojo, PROJECT_FIELD, intermediate);
    AnalyzeMojoTestFieldSupport.set(mojo, "session", session);
    final Path report = tempDir.resolve("intermediate-ban-report.json");
    Files.writeString(report, "existing report");
    AnalyzeMojoTestFieldSupport.set(mojo, REPORT_FILE_FIELD, report.toFile());
    AnalyzeMojoTestFieldSupport.set(mojo, "banishedDependencies", List.of("org.example:library"));
    // leafOnly is true by default: skips without failing on missing trace files
    assertAll(
        "leafOnly Analyze skips before requiring a ban capture or publishing a report",
        () -> Assertions.assertThatCode(mojo::execute).doesNotThrowAnyException(),
        () -> assertThat(Files.readString(report)).isEqualTo("existing report"));
  }
}
