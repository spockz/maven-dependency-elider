// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;

/** Applies graph-verified dependency changes after production classes are compiled. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.PROCESS_CLASSES,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
public final class ElideMojo extends AbstractElisionMojo {
  /** PMD key shared by test-mutable fields. */
  private static final String PMD_IMMUTABLE_FIELD = "PMD.ImmutableField";

  /** Explicit runtime evidence used when the goal is active. */
  @Parameter(property = "elide.traceFiles")
  private List<File> traceFiles;

  /** CycloneDX SBOM output generated for the elided dependency inventory. */
  @Parameter(
      property = "elide.sbomFile",
      defaultValue = "${project.build.directory}/dependency-elider-sbom.cdx.json")
  private File sbomFile;

  /** Baseline inventory SBOM written before whole-artifact removal. */
  @Parameter(
      property = "elide.baselineSbomFile",
      defaultValue = "${project.build.directory}/baseline-sbom.cdx.json")
  private File baselineSbomFile;

  /**
   * Trim-mode OpenVEX output.
   *
   * <p>Written when omitted-code or exact precondition proof succeeds.
   */
  @Parameter(
      property = "elide.vexFile",
      defaultValue = "${project.build.directory}/dependency-elider.openvex.json")
  private File vexFile;

  /**
   * Persisted elision snapshot for {@code report}, defaulting to
   * target/dependency-elider-report.json.
   */
  @Parameter(
      property = "elide.summaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-report.json")
  private File summaryFile;

  /** Mutable for tests that inject plan publication failure. */
  @SuppressWarnings(PMD_IMMUTABLE_FIELD)
  private MavenElideExecutionConfiguration.PlanPublication planPublication =
      ResolverArtifactPlanPublisher::publish;

  /** Failure hook after generation staging. */
  @SuppressWarnings(PMD_IMMUTABLE_FIELD)
  private MavenElisionOutputPublisher.AfterGenerationStaging afterGenerationStaging =
      analysis -> {};

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = DEFAULT_FALSE)
  private boolean skip;

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }

  /** Analyzes runtime evidence and applies the validated retained-artifact plan. */
  @Override
  public void execute() throws MojoFailureException {
    final MavenElideExecutionConfiguration.Lifecycle lifecycle = executionLifecycle();
    MavenElideExecution.execute(lifecycle, getLog(), () -> executionConfiguration(lifecycle));
  }

  private MavenElideExecutionConfiguration.Lifecycle executionLifecycle() {
    return new MavenElideExecutionConfiguration.Lifecycle(
        project,
        session,
        mojoExecution,
        projectDependenciesResolver,
        skip,
        leafOnly,
        banishedDependencies);
  }

  private MavenElideExecutionConfiguration executionConfiguration(
      final MavenElideExecutionConfiguration.Lifecycle lifecycle) {
    return new MavenElideExecutionConfiguration(
        lifecycle,
        analysisOptions(),
        new MavenElideExecutionConfiguration.Publication(
            new MavenElisionOutputPublisher.ReportFiles(
                reportFile,
                MavenGeneratedOutputs.Paths.outputFile(
                    sbomFile, project, "dependency-elider-sbom.cdx.json"),
                MavenGeneratedOutputs.Paths.outputFile(
                    baselineSbomFile, project, "baseline-sbom.cdx.json"),
                MavenGeneratedOutputs.Paths.outputFile(
                    vexFile, project, "dependency-elider.openvex.json"),
                summaryFile,
                trimJars),
            getLog(),
            planPublication,
            vulnerabilityCacheConfig(),
            resolveConfiguredMappings(),
            snykConfiguration(),
            preconditionClassPathComplete,
            assumeConventionalJavaSourceLayout,
            failOnForbiddenCode,
            afterGenerationStaging));
  }

  private ConfiguredVulnerabilityMappings resolveConfiguredMappings() {
    try {
      return configuredVulnerabilityMappings();
    } catch (final IOException exception) {
      throw new IllegalArgumentException(
          "Could not resolve configured vulnerability mapping catalogs: " + exception.getMessage(),
          exception);
    }
  }

  /* default */ ElisionAnalysisModel.AnalysisOptions analysisOptions() {
    final boolean trustedProcessClassesContext = trustedProcessClassesContext();
    final boolean useProductionClasses =
        productionClassesComplete || (trustedProcessClassesContext && !sourceRootsComplete);
    return new ElisionAnalysisModel.AnalysisOptions(
        traceFiles,
        retainedArtifacts,
        banishedDependencies,
        effectiveProductionOutput(useProductionClasses),
        session,
        new ElisionAnalysisModel.CompletenessOptions(
            sourceRootsComplete, useProductionClasses, trustedProcessClassesContext, true),
        sharedTrimOptions(),
        new ElisionAnalysisModel.DynamicRootOptions(conservativeServiceLoaderRoots),
        null,
        closedWorld,
        configuredRuntimePlatforms());
  }

  private File effectiveProductionOutput(final boolean useProductionClasses) {
    if (productionOutput != null || !useProductionClasses) {
      return productionOutput;
    }
    if (project == null || project.getBuild() == null) {
      return null;
    }
    final String outputDirectory = project.getBuild().getOutputDirectory();
    return outputDirectory == null || outputDirectory.isBlank() ? null : new File(outputDirectory);
  }
}
