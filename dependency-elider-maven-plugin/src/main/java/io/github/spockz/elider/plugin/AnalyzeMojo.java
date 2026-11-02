// WHY: Exposes the core's trace-grounded dependency analysis through Maven without changing its
// build state.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Analyzes a resolved Maven dependency set using explicit runtime traces. */
@Mojo(
    name = "analyze",
    requiresDependencyResolution = org.apache.maven.plugins.annotations.ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({"PMD.TooManyFields", "PMD.ImmutableField"})
public final class AnalyzeMojo extends PluginCacheMojoSupport {
  /** Maven annotation representation for disabled boolean options. */
  private static final String DEFAULT_FALSE = "false";

  /** Maven project whose resolved artifacts are analyzed. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** Resolver used to bind Analyze evidence to one captured or detached graph. */
  @Component private ProjectDependenciesResolver projectDependenciesResolver;

  /** Coordinates prediction; package tests may inject a focused result fixture. */
  private AnalyzePredictionService predictionService = new MavenElisionService()::predict;

  /** Raw execution configuration used to reject the obsolete retention parameter. */
  @Parameter(defaultValue = "${mojoExecution}", readonly = true)
  private MojoExecution mojoExecution;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  private boolean sourceRootsComplete;

  /** Asserts that production output contains every compiled production class. */
  @Parameter(property = "elide.productionClassesComplete", defaultValue = DEFAULT_FALSE)
  private boolean productionClassesComplete;

  /** Restricts dependency analysis to leaf modules in multi-module reactors. */
  @Parameter(property = "elide.leafOnly", defaultValue = "true")
  private boolean leafOnly = true;

  /** Enables dry-run intra-JAR trimming prediction. */
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
  @Parameter(property = "elide.assumeConventionalJavaSourceLayout", defaultValue = DEFAULT_FALSE)
  private boolean assumeConventionalJavaSourceLayout;

  /** Explicit trace files that supply runtime observations. */
  @Parameter(property = "elide.traceFiles", required = true)
  private List<File> traceFiles;

  /** Global artifact identities that analysis should retain. */
  @Parameter(property = "elide.retainedArtifacts")
  private List<String> retainedArtifacts;

  /** Exact groupId:artifactId bans planned only without the core extension. */
  @Parameter(property = "elide.banishedDependencies")
  private List<String> banishedDependencies;

  /** Optional production class output for static references. */
  @Parameter(property = "elide.productionOutput")
  private File productionOutput;

  /** Optional local vulnerability index directory. */
  @Parameter(property = "elide.cveCacheDirectory")
  private File cveCacheDirectory;

  /** Cache freshness interval in hours. */
  @Parameter(property = "elide.cveCacheTtlHours", defaultValue = "24")
  private int cveCacheTtlHours;

  /** Forces refresh of the vulnerability mapping index. */
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

  /** Explicit project vulnerability mappings override cached mappings. */
  @Parameter private List<VulnerabilityMappingConfig> vulnerabilityMappings;

  /** Class-usage evidence; default: target/dependency-elider-class-usage.json. */
  @Parameter(
      property = "elide.reportFile",
      defaultValue = "${project.build.directory}/dependency-elider-class-usage.json")
  private File reportFile;

  /** Creates a Mojo instance for Maven injection. */
  public AnalyzeMojo() {
    super();
  }

  /** Runs analysis and reports a conservative summary without mutating Maven state. */
  @Override
  public void execute() throws MojoFailureException {
    LegacyRetentionSetting.rejectIfConfigured(project, session, mojoExecution);
    if (shouldSkipAnalysis()) {
      return;
    }
    BanishedDependencyLifecycleActivation.verifyAnalyzeConfiguration(
        session, project, mojoExecution, banishedDependencies);
    try {
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
                      sourceRootsComplete, productionClassesComplete, false, true),
                  trimOptions(
                      trimJars,
                      trimRoots == null ? List.of() : trimRoots,
                      trimSkipArtifacts == null ? List.of() : trimSkipArtifacts,
                      failOnUnsupportedModuleInfo,
                      trimWorkers,
                      mrjarStrategy),
                  new ElisionAnalysisModel.DynamicRootOptions(conservativeServiceLoaderRoots)),
              projectDependenciesResolver);
      verifyBanPrediction(prediction);
      final ExclusionReview exclusionReview = ExclusionReview.capture(project, session);
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment =
          assessVulnerabilities(prediction);
      ElisionSummary.reportPrediction(getLog(), prediction, vulnerabilityAssessment, trimJars);
      MavenClassUsageReportWriter.write(
          reportFile.toPath(),
          prediction.evidence().classUsageReport(),
          prediction.evidence().bytecodeScan(),
          prediction,
          exclusionReview);
      if (getLog().isInfoEnabled()) {
        ExclusionReviewRenderer.render(exclusionReview).forEach(getLog()::info);
      }
      if (getLog().isInfoEnabled()) {
        getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      }
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency analysis failed closed: " + exception.getMessage(), exception);
    }
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
      final AnalyzePrediction prediction) throws IOException {
    final Path cacheDirectory =
        cveCacheDirectory == null
            ? VulnerabilityCacheManager.defaultCacheDirectory()
            : cveCacheDirectory.toPath();
    final URI osvSource =
        osvSnapshotUri == null || osvSnapshotUri.isBlank() ? null : URI.create(osvSnapshotUri);
    final URI cveListGit =
        cveListGitUri == null || cveListGitUri.isBlank() ? null : URI.create(cveListGitUri);
    final CacheConfig config =
        vulnerabilityCacheConfig(
            cacheDirectory,
            osvSource,
            cveListGit,
            Duration.ofHours(cveCacheTtlHours),
            cveForceSync,
            session != null && session.isOffline());
    return new MavenVulnerabilityAssessment(
            getLog(),
            new VulnerabilityCacheManager(),
            assumeConventionalJavaSourceLayout,
            MavenSourceCorrespondenceAssessment.configured(
                project, session, sourceClassifierResolver(), assumeConventionalJavaSourceLayout))
        .assess(config, ConfiguredVulnerabilityMappings.fromPom(vulnerabilityMappings), prediction);
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
