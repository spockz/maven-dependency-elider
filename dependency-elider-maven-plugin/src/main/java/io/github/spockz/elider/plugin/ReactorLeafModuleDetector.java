/* WHY: Evaluates whether a project in a Maven reactor is a leaf module or an
 * intermediate resource so elision can be skipped on internal libraries (ADR-0011). */

package io.github.spockz.elider.plugin;

import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.execution.ProjectDependencyGraph;
import org.apache.maven.project.MavenProject;

/** Determines whether a project is an intermediate reactor module or a leaf module. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class ReactorLeafModuleDetector {
  /** Maven packaging identifier for aggregator and parent projects. */
  private static final String POM_PACKAGING = "pom";

  private ReactorLeafModuleDetector() {}

  /**
   * Identifies intermediate reactor modules.
   *
   * @param project the Maven project being evaluated
   * @param session the current Maven session
   * @return true if the module has downstream dependents
   */
  static boolean isIntermediateReactorModule(
      final MavenProject project, final MavenSession session) {
    if (project == null || session == null) {
      return false;
    }
    final ProjectDependencyGraph graph = session.getProjectDependencyGraph();
    if (graph == null || graph.getAllProjects() == null || graph.getAllProjects().size() <= 1) {
      return false;
    }
    if (POM_PACKAGING.equalsIgnoreCase(project.getPackaging())) {
      return true;
    }
    final List<MavenProject> downstream = graph.getDownstreamProjects(project, false);
    return downstream != null && !downstream.isEmpty();
  }
}
