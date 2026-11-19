// WHY: Shares Maven parameter bindings and assessment setup across Analyze and Elide goals.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.advisory.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;
import org.eclipse.aether.RepositorySystem;

/** Shared Maven parameters and helpers for dependency elision and analysis. */
@SuppressWarnings("PMD.TooManyFields")
abstract class AbstractElisionMojo extends PluginCacheMojoSupport {
  /** Maven annotation representation for disabled boolean options. */
  protected static final String DEFAULT_FALSE = "false";

  /** Maven representation for enabled boolean options. */
  protected static final String DEFAULT_TRUE = "true";

  /** Maven project whose resolved artifacts are inspected or pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  protected MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true)
  protected MavenSession session;

  /** Resolver used to bind evidence or a ban plan to the current Maven model. */
  @Component protected ProjectDependenciesResolver projectDependenciesResolver;

  /** Resolves explicitly configured mapping catalogs as isolated data artifacts. */
  @Component protected RepositorySystem repositorySystem;

  /** Current execution source and ID for retention and preparation guards. */
  @Parameter(defaultValue = "${mojoExecution}", readonly = true)
  protected MojoExecution mojoExecution;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  protected boolean sourceRootsComplete;

  /** Asserts that production output contains every compiled production class. */
  @Parameter(property = "elide.productionClassesComplete", defaultValue = DEFAULT_FALSE)
  protected boolean productionClassesComplete;

  /**
   * Enables opt-in precondition proof.
   *
   * <p>Every Maven class-bearing input must be declared and inspectable.
   */
  @Parameter(property = "elide.preconditionClassPathComplete", defaultValue = DEFAULT_FALSE)
  protected boolean preconditionClassPathComplete;

  /** Admits explicit runtime evidence as a closed-world class boundary. */
  @Parameter(property = "elide.closedWorld", defaultValue = DEFAULT_FALSE)
  protected boolean closedWorld;

  /** Restricts dependency elision/analysis to leaf modules in multi-module reactors. */
  @Parameter(property = "elide.leafOnly", defaultValue = DEFAULT_TRUE)
  protected boolean leafOnly = true;

  /** Enables per-JAR class trimming (or dry-run prediction in analyze). */
  @Parameter(property = "elide.trimJars", defaultValue = DEFAULT_FALSE)
  protected boolean trimJars;

  /** Maximum workers used by JAR trimming stages. */
  @Parameter(property = "elide.trimWorkers", defaultValue = "4")
  protected int trimWorkers = MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS;

  /** Additional class names that must remain available for dynamic loading. */
  @Parameter(property = "elide.trimRoots")
  protected List<String> trimRoots;

  /** Retained artifact coordinates to analyze as unchanged pass-through libraries. */
  @Parameter(property = "elide.trimSkipArtifacts")
  protected List<String> trimSkipArtifacts;

  /** Demotes candidates with unresolved references to pass-through. */
  @Parameter(property = "elide.trimPassThroughOnUnresolved", defaultValue = DEFAULT_FALSE)
  protected boolean trimPassThroughOnUnresolved;

  /** Class-name patterns whose duplicate owners are retained whole. */
  @Parameter(property = "elide.retainDuplicateClassOwners")
  protected List<String> retainDuplicateClassOwners;

  /** Class-name patterns whose duplicates survive sibling trimming. */
  @Parameter(property = "elide.trimDuplicateClassOwners")
  protected List<String> trimDuplicateClassOwners;

  /** Selects MRJAR vertical shading or byte-identical pass-through. */
  @Parameter(property = "elide.mrjarStrategy", defaultValue = "vertical-shading")
  protected String mrjarStrategy = "vertical-shading";

  /** Rejects retained classpath JARs with a root module descriptor. */
  @Parameter(property = "elide.failOnUnsupportedModuleInfo", defaultValue = DEFAULT_FALSE)
  protected boolean failOnUnsupportedModuleInfo;

  /** Retains unproven ServiceLoader dynamic roots declared in META-INF/services/. */
  @Parameter(property = "elide.conservativeServiceLoaderRoots", defaultValue = DEFAULT_TRUE)
  protected boolean conservativeServiceLoaderRoots = true;

  /** Allows source-root translation only; it does not waive attribution. */
  @Parameter(property = "elide.assumeConventionalJavaSourceLayout", defaultValue = DEFAULT_TRUE)
  protected boolean assumeConventionalJavaSourceLayout;

  /** Global artifact identities that must remain in the build. */
  @Parameter(property = "elide.retainedArtifacts")
  protected List<String> retainedArtifacts;

  /** Trimmed groupId:artifactId only; each ban must be absent before publication. */
  @Parameter(property = "elide.banishedDependencies")
  protected List<String> banishedDependencies;

  /** Optional production class output for static references. */
  @Parameter(property = "elide.productionOutput")
  protected File productionOutput;

  /** Optional local vulnerability-index cache directory. */
  @Parameter(property = "elide.cveCacheDirectory")
  protected File cveCacheDirectory;

  /** Vulnerability-index cache freshness in hours. */
  @Parameter(property = "elide.cveCacheTtlHours", defaultValue = "24")
  protected int cveCacheTtlHours;

  /** Forces refresh of the vulnerability-index cache. */
  @Parameter(property = "elide.cveForceSync", defaultValue = DEFAULT_FALSE)
  protected boolean cveForceSync;

  /** Remote OSV Maven database snapshot URI. */
  @Parameter(
      property = "elide.osvSnapshotUri",
      defaultValue = "https://storage.googleapis.com/osv-vulnerabilities/Maven/all.zip")
  protected String osvSnapshotUri;

  /** Remote Git repository URI for CVEList v5. */
  @Parameter(
      property = "elide.cveListGitUri",
      defaultValue = "https://github.com/CVEProject/cvelistV5.git")
  protected String cveListGitUri;

  /** Explicit POM vulnerability mappings override cache entries. */
  @Parameter protected List<VulnerabilityMappingConfig> vulnerabilityMappings;

  /** Fails the goal when a forbidden symbol survives. */
  @Parameter(property = "elide.failOnForbiddenCode", defaultValue = DEFAULT_FALSE)
  protected boolean failOnForbiddenCode;

  /** Pinned G:A:V[:type[:classifier]] catalogs, resolved only as assessment data. */
  @Parameter(property = "elide.vulnerabilityMappingCatalogs")
  protected List<String> vulnerabilityMappingCatalogs;

  /** Enables optional per-artifact Snyk package issue queries. */
  @Parameter(property = "elide.snykEnabled", defaultValue = DEFAULT_FALSE)
  protected boolean snykEnabled;

  /** Snyk organization ID; falls back to SNYK_ORG_ID. */
  @Parameter(property = "elide.snykOrgId")
  protected String snykOrgId;

  /** Official Snyk regional package API origin. */
  @Parameter(property = "elide.snykApiBaseUri", defaultValue = "https://api.snyk.io")
  protected String snykApiBaseUri;

  /** Class-usage evidence; default: target/dependency-elider-class-usage.json. */
  @Parameter(
      property = "elide.reportFile",
      defaultValue = "${project.build.directory}/dependency-elider-class-usage.json")
  protected File reportFile;

  /** Creates a base elision Mojo instance for Maven injection. */
  protected AbstractElisionMojo() {
    super();
  }

  /** Builds the local vulnerability cache configuration from Mojo parameters. */
  protected final CacheConfig vulnerabilityCacheConfig() {
    return vulnerabilityCacheConfig(
        cveCacheDirectory, osvSnapshotUri, cveListGitUri, cveCacheTtlHours, cveForceSync, session);
  }

  /** Resolves explicit POM and catalog vulnerability mappings for the project. */
  protected final ConfiguredVulnerabilityMappings configuredVulnerabilityMappings()
      throws IOException {
    return ConfiguredVulnerabilityMappings.resolveForProject(
        repositorySystem,
        MavenAnalysisResolutionContext.repositorySession(session),
        project,
        vulnerabilityMappings,
        vulnerabilityMappingCatalogs);
  }

  /** Builds Snyk integration configuration from Mojo parameters and session. */
  protected final SnykPackageIssuesIntegration.Configuration snykConfiguration() {
    return SnykPackageIssuesIntegration.Configuration.configured(
        snykEnabled, session != null && session.isOffline(), snykOrgId, snykApiBaseUri);
  }

  /** Builds the JAR trimming options from shared Mojo parameters. */
  protected final ElisionAnalysisModel.TrimOptions sharedTrimOptions() {
    return trimOptions(
        trimJars,
        trimRoots == null ? List.of() : trimRoots,
        trimSkipArtifacts == null ? List.of() : trimSkipArtifacts,
        failOnUnsupportedModuleInfo,
        trimWorkers,
        mrjarStrategy,
        new DuplicateClassPolicy(retainDuplicateClassOwners, trimDuplicateClassOwners),
        trimPassThroughOnUnresolved);
  }

  /** Returns whether execution runs in a trusted process-classes context. */
  protected final boolean trustedProcessClassesContext() {
    return trustedProcessClassesContext(mojoExecution);
  }
}
