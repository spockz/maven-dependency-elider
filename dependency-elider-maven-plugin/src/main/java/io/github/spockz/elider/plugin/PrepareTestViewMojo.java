// WHY: Builds test-only additions after compiled test roots become available.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import io.github.spockz.elider.trimmer.JdkApiClassTableReader;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Prepares an isolated test runtime addition from the current compiled test output. */
@Mojo(
    name = "prepare-test-view",
    defaultPhase = LifecyclePhase.PROCESS_TEST_CLASSES,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.CognitiveComplexity",
  "PMD.CommentRequired",
  "PMD.CommentSize",
  "PMD.CyclomaticComplexity",
  "PMD.ExceptionAsFlowControl",
  "PMD.GuardLogStatement",
  "PMD.LawOfDemeter",
  "PMD.NcssCount",
  "PMD.NPathComplexity",
  "PMD.UseConcurrentHashMap"
})
public final class PrepareTestViewMojo extends AbstractMojo {
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  @Parameter(property = "maven.test.skip", defaultValue = "false")
  private boolean skipTestCompilation;

  @Parameter(property = "elide.runtimeInputs")
  private List<String> runtimeInputs;

  @Parameter(
      property = "elide.testViewReportFile",
      defaultValue = "${project.build.directory}/elider/test-view-report.json")
  private File testViewReportFile;

  @Override
  public void execute() throws MojoExecutionException {
    final Path addition =
        Path.of(project.getBuild().getDirectory(), "elider", "test-additions.jar")
            .toAbsolutePath()
            .normalize();
    try {
      final EliderTestViewPlan.Plan plan = EliderTestViewPlan.read(session, project);
      if (plan == null) {
        throw new IOException("Test additions require a successful Elide goal in this invocation");
      }
      final Path testOutput = Path.of(project.getBuild().getTestOutputDirectory());
      final Path mainOutput = Path.of(project.getBuild().getOutputDirectory());
      final Path freshness =
          Path.of(project.getBuild().getDirectory(), "elider", "test-view-freshness.json");
      TestViewPreparationGuard.validateOutputTargets(
          mainOutput, testOutput, List.of(addition, freshness, testViewReportFile.toPath()));
      final List<Path> previousInputs = new ArrayList<>();
      previousInputs.add(Path.of(plan.productionReport()));
      if (!plan.addition().isBlank()) {
        previousInputs.add(Path.of(plan.addition()));
      }
      for (final EliderTestViewPlan.Descriptor descriptor : plan.artifacts()) {
        previousInputs.add(Path.of(descriptor.path()));
      }
      for (final Artifact artifact : project.getArtifacts()) {
        if (artifact.getFile() != null) {
          previousInputs.add(artifact.getFile().toPath());
        }
      }
      if (project.getArtifact() != null && project.getArtifact().getFile() != null) {
        previousInputs.add(project.getArtifact().getFile().toPath());
      }
      MavenOutputTargetValidation.validate(
          List.of(addition, freshness, testViewReportFile.toPath()), previousInputs);
      Files.deleteIfExists(testViewReportFile.toPath());
      if (!plan.addition().isBlank()) {
        writeUnavailable(plan, "caller-supplied additions JAR was not analyzed");
        getLog().info("Test additions supplied by the caller: " + plan.addition());
        return;
      }
      if (skipTestCompilation) {
        Files.deleteIfExists(addition);
        writeUnavailable(plan, "test compilation was skipped");
        getLog().info("Test additions unavailable: test compilation was skipped");
        return;
      }
      TestViewPreparationGuard.requireActiveRuntime(
          runtimeInputs,
          project.getBasedir().toPath(),
          project,
          session.getUserProperties(),
          session.getSystemProperties());
      EliderTestCompilationEvidence.require(session, project);
      final Map<EliderTestViewPlan.Identity, Path> effective = new LinkedHashMap<>();
      for (final Artifact artifact : project.getArtifacts()) {
        if (artifact.getFile() != null) {
          effective.put(
              EliderTestViewPlan.Identity.of(artifact),
              artifact.getFile().toPath().toAbsolutePath().normalize());
        }
      }
      final List<TestAdditionsAnalyzer.ArtifactInput> inputs = new ArrayList<>();
      for (final EliderTestViewPlan.Descriptor descriptor : plan.artifacts()) {
        inputs.add(
            new TestAdditionsAnalyzer.ArtifactInput(
                descriptor.identity().toString(),
                Path.of(descriptor.path()),
                Optional.ofNullable(effective.get(descriptor.identity())),
                "test".equals(descriptor.identity().scope())));
      }
      final List<Path> sourceRoots =
          project.getTestCompileSourceRoots().stream().map(Path::of).toList();
      final Map<String, String> options = fingerprintOptions();
      final boolean cleaned = EliderTestCompilationEvidence.cleaned(session, project);
      final List<Path> protectedInputs = new ArrayList<>();
      protectedInputs.add(Path.of(plan.productionReport()));
      for (final TestAdditionsAnalyzer.ArtifactInput input : inputs) {
        protectedInputs.add(input.originalJar());
        input.effectiveRuntimeJar().ifPresent(protectedInputs::add);
      }
      MavenOutputTargetValidation.validate(
          List.of(addition, freshness, testViewReportFile.toPath()), protectedInputs);
      if (!cleaned) {
        TestViewFreshness.verifyOrRecord(
            freshness, false, testOutput, mainOutput, sourceRoots, inputs, options);
      }
      Files.deleteIfExists(addition);
      final TestAdditionsAnalyzer.Result result =
          TestAdditionsAnalyzer.prepare(
              testOutput,
              mainOutput,
              inputs,
              addition,
              new JdkApiClassTableReader().readFrozen(),
              ClosureQueryPolicy.conservative());
      if (cleaned) {
        TestViewFreshness.verifyOrRecord(
            freshness, true, testOutput, mainOutput, sourceRoots, inputs, options);
      }
      writePrepared(plan, inputs, result, testOutput);
      EliderTestCompilationEvidence.prepared(session, project, result.additionsJar());
      if (result.additionsJar().isPresent()) {
        getLog()
            .info(
                "Test-only additions: "
                    + result.additionsJar().orElseThrow()
                    + " classes="
                    + result.addedClassesByArtifact());
      } else {
        getLog().info("Test-only additions: none");
      }
    } catch (final IOException | IllegalArgumentException | IllegalStateException failure) {
      throw new MojoExecutionException(
          "Cannot prepare isolated test runtime: " + failure.getMessage(), failure);
    }
  }

  private Map<String, String> fingerprintOptions() {
    final Map<String, String> options = new TreeMap<>();
    options.put(
        "compilerExecution", EliderTestCompilationEvidence.compilerConfiguration(session, project));
    options.put("javaHome", System.getProperty("java.home"));
    project
        .getProperties()
        .forEach((key, value) -> options.put("project." + key, String.valueOf(value)));
    session
        .getUserProperties()
        .forEach((key, value) -> options.put("user." + key, String.valueOf(value)));
    return options;
  }

  private void writeUnavailable(final EliderTestViewPlan.Plan plan, final String reason)
      throws IOException {
    final Path report = testViewReportFile.toPath();
    final List<Path> protectedInputs = new ArrayList<>();
    protectedInputs.add(Path.of(plan.productionReport()));
    if (!plan.addition().isBlank()) {
      protectedInputs.add(Path.of(plan.addition()));
    }
    MavenOutputTargetValidation.validate(
        List.of(
            report,
            Path.of(project.getBuild().getDirectory(), "elider", "test-additions.jar"),
            Path.of(project.getBuild().getDirectory(), "elider", "test-view-freshness.json")),
        protectedInputs);
    writeReport(
        plan,
        TestViewReportSnapshot.Status.UNAVAILABLE,
        reason,
        null,
        List.of(),
        List.of(),
        null,
        false);
  }

  private void writePrepared(
      final EliderTestViewPlan.Plan plan,
      final List<TestAdditionsAnalyzer.ArtifactInput> inputs,
      final TestAdditionsAnalyzer.Result result,
      final Path testOutput)
      throws IOException {
    final List<TestViewReportSnapshot.InputArtifact> rows =
        inputs.stream()
            .map(
                input ->
                    new TestViewReportSnapshot.InputArtifact(
                        input.identity(),
                        input.originalJar().toString(),
                        input.effectiveRuntimeJar().map(Path::toString).orElse(null)))
            .toList();
    final List<TestViewReportSnapshot.Addition> additions =
        result.addedClassesByArtifact().entrySet().stream()
            .map(
                entry ->
                    new TestViewReportSnapshot.Addition(
                        entry.getKey(), List.copyOf(entry.getValue())))
            .toList();
    writeReport(
        plan,
        TestViewReportSnapshot.Status.PREPARED,
        null,
        testOutput.toAbsolutePath().normalize().toString(),
        rows,
        additions,
        result.additionsJar().map(Path::toString).orElse(null),
        result.conservativeFallbackUsed());
  }

  private void writeReport(
      final EliderTestViewPlan.Plan plan,
      final TestViewReportSnapshot.Status status,
      final String reason,
      final String testOutput,
      final List<TestViewReportSnapshot.InputArtifact> inputs,
      final List<TestViewReportSnapshot.Addition> additions,
      final String addition,
      final boolean conservativeFallbackUsed)
      throws IOException {
    final TestViewReportSnapshot snapshot =
        new TestViewReportSnapshot(
            TestViewReportSnapshot.SCHEMA_VERSION,
            project.getGroupId(),
            project.getArtifactId(),
            project.getVersion(),
            MavenElisionReportSnapshot.canonicalProjectDirectory(project).toString(),
            TestViewReportWriter.sha256(Path.of(plan.productionReport())),
            status,
            reason,
            testOutput,
            inputs,
            additions,
            addition,
            conservativeFallbackUsed);
    TestViewReportWriter.write(testViewReportFile.toPath(), snapshot);
    TestViewReportRenderer.render(snapshot).forEach(getLog()::info);
  }
}
