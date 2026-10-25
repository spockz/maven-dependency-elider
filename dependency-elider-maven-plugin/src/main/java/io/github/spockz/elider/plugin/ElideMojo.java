// WHY: Applies the trace-grounded artifact decision early enough for later Maven phases to use it.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.List;
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
public final class ElideMojo extends AbstractMojo {
  /** Maven project whose artifact views are pruned. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Maven session used to detect an externally selected compiler toolchain. */
  @Parameter(defaultValue = "${session}", readonly = true)
  private MavenSession session;

  /** User assertion that all production/generated sources exist before INITIALIZE. */
  @Parameter(property = "elide.sourceRootsComplete", defaultValue = "false")
  private boolean sourceRootsComplete;

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

  /** Maven switch that skips analysis and mutation. */
  @Parameter(property = "elide.skip", defaultValue = "false")
  private boolean skip;

  /** Analyzes runtime evidence and applies the validated retained-artifact plan. */
  @Override
  public void execute() throws MojoFailureException {
    if (skip) {
      return;
    }
    try {
      final MavenElisionService service = new MavenElisionService();
      final MavenElisionService.Analysis analysis =
          service.analyze(
              project,
              traceFiles,
              excludedArtifacts,
              productionOutput,
              session,
              sourceRootsComplete);
      final MavenElisionService.ApplyPlan plan = service.plan(project, analysis);
      MavenClassUsageReportWriter.write(
          reportFile.toPath(), analysis.classUsageReport(), analysis.bytecodeScan());
      project.setArtifacts(new LinkedHashSet<>(plan.resolvedArtifacts()));
      if (plan.directArtifactsPresent()) {
        project.setDependencyArtifacts(new LinkedHashSet<>(plan.directArtifacts()));
      }
      ElisionSummary.report(getLog(), analysis.decision(), analysis.resolvedSnapshots().size());
      if (getLog().isInfoEnabled()) {
        getLog().info("  Class usage report: " + reportFile.toPath().toAbsolutePath().normalize());
      }
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision failed: " + exception.getMessage(), exception);
    }
  }

  /** Creates a Mojo instance for Maven injection. */
  public ElideMojo() {
    super();
  }
}
