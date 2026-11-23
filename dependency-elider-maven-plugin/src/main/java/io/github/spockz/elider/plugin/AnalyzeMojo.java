// WHY: Exposes the core's trace-grounded dependency analysis through Maven without changing its
// build state.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

/** Analyzes a resolved Maven dependency set using explicit runtime traces. */
@Mojo(
    name = "analyze",
    requiresDependencyResolution = org.apache.maven.plugins.annotations.ResolutionScope.TEST,
    threadSafe = true)
public final class AnalyzeMojo extends AbstractElisionMojo {
  /** Coordinates prediction; package tests may inject a focused result fixture. */
  @SuppressWarnings("PMD.ImmutableField")
  private AnalyzePredictionService predictionService = new MavenElisionService()::predict;

  /** Explicit trace files that supply runtime observations. */
  @Parameter(property = "elide.traceFiles", required = true)
  private List<File> traceFiles;

  /** Saved analysis summary; kept separate from the last applied elision report. */
  @Parameter(
      property = "elide.analysisSummaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-analysis-report.json")
  private File analysisSummaryFile;

  /** Creates a Mojo instance for Maven injection. */
  public AnalyzeMojo() {
    super();
  }

  /** Runs analysis and reports a conservative summary without mutating Maven state. */
  @Override
  public void execute() throws MojoFailureException {
    if (sourceRootsComplete) {
      throw new MojoFailureException(
          "elide.sourceRootsComplete is no longer supported; bind elide to process-classes");
    }
    if (shouldSkipAnalysis()) {
      return;
    }
    BanishedDependencyLifecycleActivation.verifyAnalyzeConfiguration(
        session, project, mojoExecution, banishedDependencies);
    try {
      final boolean trustedProcessClasses = trustedProcessClassesContext();
      final AnalyzePrediction prediction =
          predictionService.predict(
              project,
              new ElisionAnalysisModel.AnalysisOptions(
                  traceFiles,
                  retainedArtifacts,
                  banishedDependencies,
                  productionOutput,
                  session,
                  new ElisionAnalysisModel.CompletenessOptions(
                      sourceRootsComplete,
                      productionClassesComplete || trustedProcessClasses,
                      trustedProcessClasses,
                      true),
                  sharedTrimOptions(),
                  new ElisionAnalysisModel.DynamicRootOptions(conservativeServiceLoaderRoots),
                  null,
                  closedWorld,
                  configuredRuntimePlatforms()),
              projectDependenciesResolver);
      verifyBanPrediction(prediction);
      final ExclusionReview exclusionReview = ExclusionReview.capture(project, session);
      final ConfiguredVulnerabilityMappings mappings = configuredVulnerabilityMappings();
      final List<ForbiddenCodeAssessment> forbiddenCode =
          MavenForbiddenCodeAssessment.predict(
              project, prediction, mappings, failOnForbiddenCode, productionOutput);
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment =
          assessVulnerabilities(prediction, mappings);
      final MavenElisionReportSnapshot snapshot =
          MavenElisionReportSnapshot.from(
                  project, prediction, vulnerabilityAssessment, exclusionReview)
              .withForbiddenCodeAssessments(forbiddenCode);
      final Path summary = analysisSummaryPath();
      publishReports(prediction, exclusionReview, snapshot, summary);
      logReport(prediction, snapshot, summary);
      MavenForbiddenCodeAssessment.enforce(forbiddenCode, getLog());
    } catch (final ElisionReachabilityEngine.PlatformLinkageUnavailable unavailable) {
      throw failedLinkage(unavailable);
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency analysis failed closed: " + exception.getMessage(), exception);
    }
  }

  private MojoFailureException failedLinkage(
      final ElisionReachabilityEngine.PlatformLinkageUnavailable unavailable) {
    try {
      MavenForbiddenCodeAssessment.reportBlockedLinkage(
          unavailable,
          configuredVulnerabilityMappings(),
          failOnForbiddenCode,
          ForbiddenCodeAssessment.Mode.PREDICTED,
          getLog());
    } catch (final IOException policyFailure) {
      policyFailure.addSuppressed(unavailable);
      return new MojoFailureException(
          "Dependency analysis failed closed: " + policyFailure.getMessage(), policyFailure);
    }
    return new MojoFailureException(
        "Dependency analysis failed closed: " + unavailable.getMessage(), unavailable);
  }

  private void publishReports(
      final AnalyzePrediction prediction,
      final ExclusionReview exclusionReview,
      final MavenElisionReportSnapshot snapshot,
      final Path summary)
      throws IOException, MojoFailureException {
    MavenOutputTargetValidation.validate(List.of(reportFile.toPath(), summary));
    MavenClassUsageReportWriter.write(
        reportFile.toPath(),
        prediction.evidence().classUsageReport(),
        prediction.evidence().bytecodeScan(),
        prediction,
        exclusionReview);
    MavenElisionReportWriter.write(summary, snapshot);
  }

  private void logReport(
      final AnalyzePrediction prediction,
      final MavenElisionReportSnapshot snapshot,
      final Path summary) {
    MavenElisionOutputLogger.dynamicRootWarnings(getLog(), prediction.evidence());
    final String fallback = prediction.evidence().sourceAttributionFallback();
    if (fallback != null && getLog().isWarnEnabled()) {
      getLog()
          .warn(
              "Post-compile source attribution used conservative fallback; all compile-visible "
                  + "artifacts and indexed classes were retained: "
                  + fallback);
    }
    if (getLog().isInfoEnabled()) {
      MavenElisionReportWriter.render(snapshot).forEach(getLog()::info);
      getLog()
          .info(
              trimJars
                  ? "  JAR trim cache: unavailable (Analyze reports an in-memory prediction only)"
                  : "  JAR trim cache: unavailable (trim stage not run)");
      getLog().info("  Analysis report: " + summary.toAbsolutePath().normalize());
      getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      getLog().info("  Test view: unavailable: tests were not compiled during analyze");
    }
  }

  private Path analysisSummaryPath() {
    if (analysisSummaryFile != null) {
      return analysisSummaryFile.toPath();
    }
    final String directory = project.getBuild() == null ? null : project.getBuild().getDirectory();
    return directory == null
        ? Path.of("target", "dependency-elider-analysis-report.json")
        : Path.of(directory, "dependency-elider-analysis-report.json");
  }

  private void verifyBanPrediction(final AnalyzePrediction prediction) throws MojoFailureException {
    final List<BanishedDependency> requested =
        BanishedDependencyPolicy.normalize(banishedDependencies);
    if (requested.isEmpty()) {
      return;
    }
    if (!Set.of(
                MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
                MavenAnalysisResolutionContext.Provenance.CAPTURED_EFFECTIVE_RESOLVER)
            .contains(prediction.provenance())
        || !prediction.banPlan().entries().stream()
            .map(MavenBanPlan.Entry::dependency)
            .toList()
            .equals(requested)
        || !prediction
            .wouldElideArtifacts()
            .containsAll(prediction.banPlan().forcedAbsentAfterResolution())) {
      throw new MojoFailureException(
          "Analyze prediction does not prove the requested detached ban plan");
    }
  }

  private MavenVulnerabilityAssessment.Result assessVulnerabilities(
      final AnalyzePrediction prediction, final ConfiguredVulnerabilityMappings mappings)
      throws IOException {
    return new MavenVulnerabilityAssessment(getLog(), assumeConventionalJavaSourceLayout)
        .assess(
            vulnerabilityCacheConfig(),
            mappings,
            prediction,
            () ->
                MavenPreconditionPrediction.capture(
                    project, session, prediction, preconditionClassPathComplete),
            snykConfiguration());
  }

  private boolean shouldSkipAnalysis() {
    if (leafOnly && ReactorLeafModuleDetector.isIntermediateReactorModule(project, session)) {
      if (getLog().isInfoEnabled()) {
        getLog()
            .info(
                "Skipping dependency analysis on intermediate reactor module: "
                    + (project == null ? "unknown" : project.getArtifactId()));
      }
      return true;
    }
    return false;
  }
}
