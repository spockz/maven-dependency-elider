// WHY: Exposes the core's trace-grounded dependency analysis through Maven without changing its
// build state.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.util.List;
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
public final class AnalyzeMojo extends AbstractMojo {
  /** Maven project whose resolved artifacts are analyzed. */
  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  /** Explicit trace files that supply runtime observations. */
  @Parameter(property = "elide.traceFiles", required = true)
  private List<File> traceFiles;

  /** Global artifact identities that analysis should retain. */
  @Parameter(property = "elide.excludedArtifacts")
  private List<String> excludedArtifacts;

  /** Creates a Mojo instance for Maven injection. */
  public AnalyzeMojo() {
    super();
  }

  /** Runs analysis and reports a conservative summary without mutating Maven state. */
  @Override
  public void execute() throws MojoFailureException {
    try {
      final MavenElisionService.Analysis analysis =
          new MavenElisionService().analyze(project, traceFiles, excludedArtifacts);
      ElisionSummary.report(getLog(), analysis.decision(), analysis.resolvedSnapshots().size());
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency analysis failed closed: " + exception.getMessage(), exception);
    }
  }
}
