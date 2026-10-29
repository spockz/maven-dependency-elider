// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Applies graph-verified dependency changes during Maven initialization. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.INITIALIZE,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({"PMD.TooManyFields", "PMD.CouplingBetweenObjects", "PMD.ImmutableField"})
public final class ElideMojo extends AbstractMojo {
  /** Maven's annotation representation for disabled boolean options. */
  private static final String DEFAULT_FALSE = "false";

  /** Maven project whose artifact views are pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  /** Current execution source and ID for the injected preparation duplicate guard. */
  @Parameter(defaultValue = "${mojoExecution}", readonly = true, required = true)
  private MojoExecution mojoExecution;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  private boolean sourceRootsComplete;

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

  /** Fails instead of retaining multi-release implementation JARs without trimming. */
  @Parameter(property = "elide.failOnUnsupportedMultiRelease", defaultValue = DEFAULT_FALSE)
  private boolean failOnUnsupportedMultiRelease;

  /** Rejects retained classpath JARs with a root module descriptor. */
  @Parameter(property = "elide.failOnUnsupportedModuleInfo", defaultValue = DEFAULT_FALSE)
  private boolean failOnUnsupportedModuleInfo;

  /** Retains unproven ServiceLoader dynamic roots declared in META-INF/services/. */
  @Parameter(property = "elide.conservativeServiceLoaderRoots", defaultValue = "true")
  private boolean conservativeServiceLoaderRoots = true;

  /** Explicit runtime evidence used when the goal is active. */
  @Parameter(property = "elide.traceFiles")
  private List<File> traceFiles;

  /** Global artifact identities that must remain in the build. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

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

  /** OpenVEX output written only when omitted-code proof succeeds. */
  @Parameter(
      property = "elide.vexFile",
      defaultValue = "${project.build.directory}/dependency-elider.openvex.json")
  private File vexFile;

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
  @SuppressWarnings("PMD.ImmutableField")
  private PlanPublication planPublication = ResolverArtifactPlanPublisher::publish;

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = DEFAULT_FALSE)
  private boolean skip;

  /** Package callback used to test publication ordering. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  @FunctionalInterface
  interface PlanPublication {
    /** Installs the resolver plan after report and view staging succeeds. */
    void publish(
        MavenSession session,
        MavenProject project,
        List<io.github.spockz.elider.trimmer.ArtifactTrimRecord> trimRecords,
        ResolverArtifactGraphProjection graphProjection)
        throws IOException;
  }

  /** Analyzes runtime evidence and applies the validated retained-artifact plan. */
  @Override
  public void execute() throws MojoFailureException {
    final String executionId = mojoExecution == null ? null : mojoExecution.getExecutionId();
    final String projectId = project == null ? null : project.getId();
    final MojoExecution.Source executionSource = EliderPreparationState.source(mojoExecution);
    if (EliderPreparationState.consumePreparedLifecycleDuplicate(
        session, executionId, projectId, executionSource)) {
      return;
    }
    try {
      if (skip) {
        publishEmptyPlan();
        EliderPreparationState.completeInjectedCliPreparation(
            session, executionId, projectId, executionSource);
        return;
      }
      executeAnalysis();
      EliderPreparationState.completeInjectedCliPreparation(
          session, executionId, projectId, executionSource);
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision failed: " + exception.getMessage(), exception);
    }
  }

  private void publishEmptyPlan() throws IOException {
    ResolverArtifactPlanPublisher.publish(session, project, List.of());
  }

  private void executeAnalysis() throws IOException, MojoFailureException {
    final List<ArtifactFileRef> baselineInventory =
        trimJars ? MavenSbomWriter.captureOriginalInventory(project) : List.of();
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(project, analysisOptions());
    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final MavenElisionService.Analysis analysis = service.finishEffectiveOutputs(effective);
    final MavenVulnerabilityAssessment.Result vulnerabilityAssessment =
        assessVulnerabilities(analysis);
    try (TrimOutputGenerationCommitHandle generation = analysis.generationCommit()) {
      MavenElisionOutputPublisher.publish(
          new MavenElisionOutputPublisher.Request(
              project,
              session,
              service,
              analysis,
              generation,
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
              baselineInventory,
              vulnerabilityAssessment));
    }
  }

  private MavenVulnerabilityAssessment.Result assessVulnerabilities(
      final MavenElisionService.Analysis analysis) throws IOException {
    final Path cacheDirectory =
        cveCacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cveCacheDirectory.toPath();
    final URI osvSource =
        osvSnapshotUri == null || osvSnapshotUri.isBlank() ? null : URI.create(osvSnapshotUri);
    final URI cveListGit =
        cveListGitUri == null || cveListGitUri.isBlank() ? null : URI.create(cveListGitUri);
    final CacheConfig config =
        new CacheConfig(
            cacheDirectory,
            osvSource,
            cveListGit,
            Duration.ofHours(cveCacheTtlHours),
            cveForceSync,
            session != null && session.isOffline(),
            VulnerabilityCacheManager.bundledEmptySeed());
    final List<VulnerabilitySymbolMapping> manualMappings =
        vulnerabilityMappings == null
            ? List.of()
            : vulnerabilityMappings.stream().map(VulnerabilityMappingConfig::toMapping).toList();
    return new MavenVulnerabilityAssessment(getLog()).assess(config, manualMappings, analysis);
  }

  private MavenElisionService.AnalysisOptions analysisOptions() {
    return new MavenElisionService.AnalysisOptions(
        traceFiles,
        excludedArtifacts,
        productionOutput,
        session,
        sourceRootsComplete,
        trimJars,
        trimRoots == null ? List.of() : trimRoots,
        failOnUnsupportedMultiRelease,
        trimSkipArtifacts == null ? List.of() : trimSkipArtifacts,
        failOnUnsupportedModuleInfo,
        true,
        conservativeServiceLoaderRoots,
        trimWorkers);
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
