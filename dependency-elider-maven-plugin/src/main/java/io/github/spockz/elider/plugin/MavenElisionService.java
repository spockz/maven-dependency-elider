// WHY: Coordinates checked Maven analysis and trimming while collaborators own
// scanning and graph policy.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.nativeimage.DependencyDynamicRoots;
import java.io.IOException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Coordinates shared trace analysis and a nonmutating Maven artifact plan. */
public final class MavenElisionService {
  /** Creates a Maven elision service with default collaborators. */
  public MavenElisionService() {
    super();
  }

  /** Runs full dependency elision analysis for the given project and options. */
  public Analysis analyze(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return finish(prepare(project, options));
  }

  /** Predicts dependency elision outcomes without mutating output artifacts. */
  public AnalyzePrediction predict(
      final MavenProject project,
      final AnalysisOptions options,
      final ProjectDependenciesResolver resolver)
      throws IOException, MojoFailureException {
    try (MavenBanPreparation preparation =
        MavenBanPreparation.prepare(project, options, resolver)) {
      return AnalyzePrediction.from(
          ElisionReachabilityEngine.finishAnalysis(preparation.analysis()));
    }
  }

  /** Prepares dependency inventory and analysis inputs for execution. */
  public PreparedAnalysis prepare(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return prepare(project, options, DependencyDynamicRoots::scan);
  }

  /** Prepares dependency inventory and analysis inputs for execution. */
  public PreparedAnalysis prepare(
      final MavenProject project,
      final AnalysisOptions options,
      final DynamicRootScanner dynamicRootScanner)
      throws IOException, MojoFailureException {
    return MavenAnalysisPreparation.prepare(project, options, dynamicRootScanner);
  }

  /** Prepares dependency inventory and analysis inputs for execution. */
  public PreparedAnalysis prepare(
      final MavenProject project,
      final AnalysisOptions options,
      final MavenAnalysisResolutionContext context,
      final MavenBanPlan banPlan)
      throws IOException, MojoFailureException {
    return MavenAnalysisPreparation.prepare(
        project, options, DependencyDynamicRoots::scan, context, banPlan);
  }

  /** Completes analysis and publishes outputs from a prepared state. */
  public Analysis finish(final PreparedAnalysis prepared) throws IOException, MojoFailureException {
    return finishEffectiveOutputs(finishAnalysis(prepared));
  }

  /** Runs effective analysis without publishing final artifact outputs. */
  public EffectiveAnalysis finishAnalysis(final PreparedAnalysis prepared)
      throws IOException, MojoFailureException {
    return ElisionReachabilityEngine.finishAnalysis(prepared);
  }

  /** Publishes outputs from a completed effective analysis. */
  public Analysis finishEffectiveOutputs(final EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return ElisionReachabilityEngine.finishEffectiveOutputs(effective);
  }
}
