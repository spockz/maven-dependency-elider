// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Applies graph-verified dependency changes during Maven initialization. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.INITIALIZE,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({"PMD.TooManyFields", "PMD.ImmutableField"})
public final class ElideMojo extends PluginCacheMojoSupport {
  /** PMD key shared by test-mutable fields. */
  private static final String PMD_IMMUTABLE_FIELD = "PMD.ImmutableField";

  /** Maven's annotation representation for disabled boolean options. */
  private static final String DEFAULT_FALSE = "false";

  /** Maven representation for enabled boolean options. */
  private static final String DEFAULT_TRUE = "true";

  /** Maven project whose artifact views are pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  /** Resolver used to bind an isolated ban plan to the current Maven model. */
  @Component private ProjectDependenciesResolver projectDependenciesResolver;

  /** Current execution source and ID for the injected preparation duplicate guard. */
  @Parameter(defaultValue = "${mojoExecution}", readonly = true, required = true)
  private MojoExecution mojoExecution;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  private boolean sourceRootsComplete;

  /** Asserts that production output contains every compiled production class. */
  @Parameter(property = "elide.productionClassesComplete", defaultValue = DEFAULT_FALSE)
  private boolean productionClassesComplete;

  /**
   * Enables per-JAR class trimming.
   *
   * <p>Metadata roots protect declaring and provider JARs when disabled.
   */
  @Parameter(property = "elide.trimJars", defaultValue = DEFAULT_FALSE)
  private boolean trimJars;

  /** Maximum workers used by JAR trimming stages. */
  @Parameter(property = "elide.trimWorkers", defaultValue = "4")
  private int trimWorkers = MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS;

  /** Additional class names that must remain available for dynamic loading. */
  @Parameter(property = "elide.trimRoots")
  private List<String> trimRoots;

  /** Retained artifact coordinates to analyze as unchanged pass-through libraries. */
  @Parameter(property = "elide.trimSkipArtifacts")
  private List<String> trimSkipArtifacts;

  /** Selects MRJAR vertical shading or byte-identical pass-through. */
  @Parameter(property = "elide.mrjarStrategy", defaultValue = "vertical-shading")
  private String mrjarStrategy = "vertical-shading";

  /** Rejects retained classpath JARs with a root module descriptor. */
  @Parameter(property = "elide.failOnUnsupportedModuleInfo", defaultValue = DEFAULT_FALSE)
  private boolean failOnUnsupportedModuleInfo;

  /** Retains unproven ServiceLoader dynamic roots declared in META-INF/services/. */
  @Parameter(property = "elide.conservativeServiceLoaderRoots", defaultValue = "true")
  private boolean conservativeServiceLoaderRoots = true;

  /** Allows source-root translation only; it does not waive attribution. */
  @Parameter(property = "elide.assumeConventionalJavaSourceLayout", defaultValue = DEFAULT_TRUE)
  private boolean assumeConventionalJavaSourceLayout;

  /** Explicit runtime evidence used when the goal is active. */
  @Parameter(property = "elide.traceFiles")
  private List<File> traceFiles;

  /** Global artifact identities that must remain in the build. */
  @Parameter(property = "elide.retainedArtifacts")
  private List<String> retainedArtifacts;

  /** Trimmed groupId:artifactId only; each ban must be absent before publication. */
  @Parameter(property = "elide.banishedDependencies")
  private List<String> banishedDependencies;

  /** Optional production class output for static references. */
  @Parameter(property = "elide.productionOutput")
  private File productionOutput;

  /** Class-usage evidence; default: target/dependency-elider-class-usage.json. */
  @Parameter(
      property = "elide.reportFile",
      defaultValue = "${project.build.directory}/dependency-elider-class-usage.json")
  private File reportFile;

  /** SBOM output generated when trimming is enabled. */
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
   * Enables opt-in proof.
   *
   * <p>Every Maven class-bearing input must be declared and inspectable.
   */
  @Parameter(property = "elide.preconditionClassPathComplete", defaultValue = DEFAULT_FALSE)
  private boolean preconditionClassPathComplete;

  /** Optional local vulnerability-index cache directory. */
  @Parameter(property = "elide.cveCacheDirectory")
  private File cveCacheDirectory;

  /** Vulnerability-index cache freshness in hours. */
  @Parameter(property = "elide.cveCacheTtlHours", defaultValue = "24")
  private int cveCacheTtlHours;

  /** Forces refresh of the vulnerability-index cache. */
  @Parameter(property = "elide.cveForceSync", defaultValue = DEFAULT_FALSE)
  private boolean cveForceSync;

  /** Remote OSV Maven database snapshot URI. */
  @Parameter(
      property = "elide.osvSnapshotUri",
      defaultValue = "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip")
  private String osvSnapshotUri;

  /** Remote Git repository URI for CVEList v5. */
  @Parameter(
      property = "elide.cveListGitUri",
      defaultValue = "https://github.com/CVEProject/cvelistV5.git")
  private String cveListGitUri;

  /** Explicit POM vulnerability mappings override cache entries. */
  @Parameter private List<VulnerabilityMappingConfig> vulnerabilityMappings;

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

  /**
   * Test mutation hook for report stages.
   *
   * <p>Verifies inventory freshness before publication.
   */
  @SuppressWarnings(PMD_IMMUTABLE_FIELD)
  private MavenElisionOutputPublisher.AfterStaging afterStaging = () -> {};

  /** Failure hook after generation staging. */
  @SuppressWarnings(PMD_IMMUTABLE_FIELD)
  private MavenElisionOutputPublisher.AfterStaging afterGenerationStaging = () -> {};

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = DEFAULT_FALSE)
  private boolean skip;

  /** Restricts dependency elision to leaf modules in multi-module reactors. */
  @Parameter(property = "elide.leafOnly", defaultValue = "true")
  private boolean leafOnly = true;

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
                MavenGeneratedOutputs.outputFile(
                    sbomFile, project, "dependency-elider-sbom.cdx.json"),
                MavenGeneratedOutputs.outputFile(
                    baselineSbomFile, project, "baseline-sbom.cdx.json"),
                MavenGeneratedOutputs.outputFile(
                    vexFile, project, "dependency-elider.openvex.json"),
                summaryFile,
                trimJars),
            getLog(),
            planPublication,
            vulnerabilityCacheConfig(),
            configuredVulnerabilityMappings(),
            trimJars && preconditionClassPathComplete,
            assumeConventionalJavaSourceLayout,
            sourceClassifierResolver(),
            afterStaging,
            afterGenerationStaging));
  }

  private CacheConfig vulnerabilityCacheConfig() {
    final Path cacheDirectory =
        cveCacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cveCacheDirectory.toPath();
    final URI osvSource =
        osvSnapshotUri == null || osvSnapshotUri.isBlank() ? null : URI.create(osvSnapshotUri);
    final URI cveListGit =
        cveListGitUri == null || cveListGitUri.isBlank() ? null : URI.create(cveListGitUri);
    return vulnerabilityCacheConfig(
        cacheDirectory,
        osvSource,
        cveListGit,
        Duration.ofHours(cveCacheTtlHours),
        cveForceSync,
        session != null && session.isOffline());
  }

  private ConfiguredVulnerabilityMappings configuredVulnerabilityMappings() {
    return ConfiguredVulnerabilityMappings.fromPom(vulnerabilityMappings);
  }

  private ElisionAnalysisModel.AnalysisOptions analysisOptions() {
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
        trimOptions(
            trimJars,
            trimRoots == null ? List.of() : trimRoots,
            trimSkipArtifacts == null ? List.of() : trimSkipArtifacts,
            failOnUnsupportedModuleInfo,
            trimWorkers,
            mrjarStrategy),
        new ElisionAnalysisModel.DynamicRootOptions(conservativeServiceLoaderRoots));
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

  private boolean trustedProcessClassesContext() {
    return mojoExecution != null
        && EliderPreparationState.source(mojoExecution) == MojoExecution.Source.LIFECYCLE
        && "process-classes".equals(mojoExecution.getLifecyclePhase());
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
