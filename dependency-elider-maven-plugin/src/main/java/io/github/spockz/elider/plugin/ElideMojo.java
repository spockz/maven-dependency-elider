// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
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
@SuppressWarnings("PMD.TooManyFields")
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
    final MavenElisionService service = new MavenElisionService();
    final MavenElisionService.PreparedAnalysis prepared =
        service.prepare(project, analysisOptions());
    final MavenElisionService.EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final MavenElisionService.Analysis analysis = service.finishEffectiveOutputs(effective);
    try (TrimOutputGenerationCommitHandle generation = analysis.generationCommit()) {
      MavenElisionOutputPublisher.publish(
          new MavenElisionOutputPublisher.Request(
              project,
              session,
              service,
              analysis,
              generation,
              new MavenElisionOutputPublisher.ReportFiles(
                  reportFile, sbomFile, summaryFile, trimJars),
              getLog(),
              planPublication));
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

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
