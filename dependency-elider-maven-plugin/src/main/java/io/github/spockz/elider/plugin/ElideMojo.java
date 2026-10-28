// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

/** Removes unobserved dependency JARs from Maven's in-memory artifact views. */
@Mojo(
    name = "elide",
    defaultPhase = LifecyclePhase.INITIALIZE,
    requiresDependencyResolution = ResolutionScope.TEST,
    threadSafe = true)
@SuppressWarnings({"PMD.CollapsibleIfStatements", "PMD.GuardLogStatement"})
public final class ElideMojo extends AbstractMojo {
  /** Maven's annotation representation for disabled boolean options. */
  private static final String DEFAULT_FALSE = "false";

  /** Maven project whose artifact views are pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true, required = true)
  private MavenSession session;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = DEFAULT_FALSE)
  private boolean sourceRootsComplete;

  /** Enables per-JAR trimming for retained dependency archives. */
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

  /** Explicit runtime evidence used when the goal is active. */
  @Parameter(property = "elide.traceFiles")
  private List<File> traceFiles;

  /** Global artifact identities that must remain in the build. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

  /** Optional production class output for static references. */
  @Parameter(property = "elide.productionOutput")
  private File productionOutput;

  /** Structured report path, defaulting to the Maven build directory. */
  @Parameter(
      property = "elide.reportFile",
      defaultValue = "${project.build.directory}/dependency-elider-class-usage.json")
  private File reportFile;

  /** SBOM output generated when trimming is enabled. */
  @Parameter(
      property = "elide.sbomFile",
      defaultValue = "${project.build.directory}/dependency-elider-sbom.cdx.json")
  private File sbomFile;

  /** Persisted totals consumed by the separate Maven {@code report} goal. */
  @Parameter(
      property = "elide.summaryFile",
      defaultValue = "${project.build.directory}/dependency-elider-report.json")
  private File summaryFile;

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = DEFAULT_FALSE)
  private boolean skip;

  /** Analyzes runtime evidence and applies the validated retained-artifact plan. */
  @Override
  public void execute() throws MojoFailureException {
    try {
      if (skip) {
        ResolverArtifactPlanPublisher.publish(session, project, List.of());
        return;
      }
      final MavenElisionService service = new MavenElisionService();
      final MavenElisionService.Analysis analysis = service.analyze(project, analysisOptions());
      logPassThroughWarnings(analysis);
      final MavenElisionService.ApplyPlan plan = service.plan(project, analysis);
      final MavenElisionReportSnapshot reportSnapshot =
          MavenElisionReportSnapshot.from(project, analysis);
      MavenClassUsageReportWriter.write(
          reportFile.toPath(), analysis.classUsageReport(), analysis.bytecodeScan());
      if (trimJars) {
        MavenSbomWriter.write(project, sbomFile.toPath(), plan, analysis);
      }
      MavenArtifactViewUpdater.apply(plan, analysis.trimRecords());
      final Set<Artifact> retainedResolvedArtifacts = new LinkedHashSet<>(plan.resolvedArtifacts());
      project.setResolvedArtifacts(retainedResolvedArtifacts);
      project.setArtifacts(retainedResolvedArtifacts);
      if (trimJars) {
        if (analysis.trimCacheHits() > 0) {
          final double milliseconds = analysis.maximumTrimCacheHitNanos() / 1_000_000.0;
          getLog()
              .info(
                  "  JAR trim cache: "
                      + analysis.trimCacheHits()
                      + " hit(s), maximum validated hit "
                      + milliseconds
                      + " ms (target < 1.5 ms)");
        }
      }
      if (trimJars) {
        ElisionSummary.reportTrimmed(
            getLog(), analysis.decision(), analysis.resolvedSnapshots().size(), reportSnapshot);
      } else {
        ElisionSummary.report(getLog(), analysis.decision(), analysis.resolvedSnapshots().size());
      }
      if (getLog().isInfoEnabled()) {
        getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      }
      MavenElisionReportWriter.write(
          MavenElisionReportWriter.outputPath(summaryFile, project), reportSnapshot);
      ResolverArtifactPlanPublisher.publish(session, project, analysis.trimRecords());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision failed: " + exception.getMessage(), exception);
    }
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
        true);
  }

  private void logPassThroughWarnings(final MavenElisionService.Analysis analysis) {
    analysis
        .multiReleasePassthroughArtifacts()
        .forEach(
            coordinate ->
                getLog()
                    .warn(
                        "Keeping multi-release dependency unchanged with Java "
                            + Runtime.version().feature()
                            + " effective classes for closure; unchanged external links are "
                            + "tolerated: "
                            + coordinate));
    analysis
        .moduleInfoPassthroughArtifacts()
        .forEach(
            coordinate ->
                getLog()
                    .warn(
                        "Keeping root-module-info dependency unchanged; its class-only projection "
                            + "covers classpath closure, not module-path closure: "
                            + coordinate));
    analysis
        .configuredPassThroughArtifacts()
        .forEach(
            coordinate ->
                getLog()
                    .warn(
                        "Keeping configured dependency unchanged; external links from unchanged "
                            + "classes are tolerated: "
                            + coordinate));
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
