// WHY: Lets Mojo tests prove guard ordering without subclassing the final analysis facade.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import java.io.IOException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Narrow prediction seam used to verify Analyze guard ordering. */
@FunctionalInterface
interface AnalyzePredictionService {
  /** Computes one nonpublishing prediction for the requested Maven project. */
  AnalyzePrediction predict(
      MavenProject project, AnalysisOptions options, ProjectDependenciesResolver resolver)
      throws IOException, MojoFailureException;
}
