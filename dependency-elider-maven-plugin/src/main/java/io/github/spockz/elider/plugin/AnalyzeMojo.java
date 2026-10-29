// WHY: Exposes the core's trace-grounded dependency analysis through Maven without changing its
// build state.

package io.github.spockz.elider.plugin;

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
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

/** Analyzes a resolved Maven dependency set using explicit runtime traces. */
@Mojo(
    name = "analyze",
    requiresDependencyResolution = org.apache.maven.plugins.annotations.ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({"PMD.TooManyFields", "PMD.ImmutableField"})
public final class AnalyzeMojo extends AbstractMojo {
  /** Maven annotation representation for disabled boolean options. */
  private static final String DEFAULT_FALSE = "false";

  /** Maven project whose resolved artifacts are analyzed. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  private boolean sourceRootsComplete;

  /** Enables dry-run intra-JAR trimming prediction. */
  @Parameter(property = "elide.trimJars", defaultValue = DEFAULT_FALSE)
  private boolean trimJars;

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

  /** Explicit trace files that supply runtime observations. */
  @Parameter(property = "elide.traceFiles", required = true)
  private List<File> traceFiles;

  /** Global artifact identities that analysis should retain. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

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
    try {
      final MavenElisionService.Analysis analysis =
          new MavenElisionService()
              .analyze(
                  project,
                  new MavenElisionService.AnalysisOptions(
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
                      conservativeServiceLoaderRoots));
      MavenClassUsageReportWriter.write(
          reportFile.toPath(), analysis.classUsageReport(), analysis.bytecodeScan());
      final MavenVulnerabilityAssessment.Result vulnerabilityAssessment =
          assessVulnerabilities(analysis);
      ElisionSummary.reportAnalysis(getLog(), analysis, vulnerabilityAssessment, trimJars);
      if (getLog().isInfoEnabled()) {
        getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      }
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency analysis failed closed: " + exception.getMessage(), exception);
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
}
