// WHY: Coordinates checked Maven analysis and trimming while collaborators own
// scanning and graph policy.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Coordinates shared trace analysis and a nonmutating Maven artifact plan. */
final class MavenElisionService extends MavenElisionServiceDefaults {
  /** Declares the package-scoped constructor required for this stateless facade. */
  /* package */ MavenElisionService() {
    super();
  }

  @Override
  /* default */ Analysis analyze(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return finish(prepare(project, options));
  }

  /* package */ AnalyzePrediction predict(
      final MavenProject project,
      final AnalysisOptions options,
      final ProjectDependenciesResolver resolver)
      throws IOException, MojoFailureException {
    final MavenProject currentModel = MavenAnalysisResolutionContext.currentModel(project);
    BanishedDependencyPolicy.resolve(
        options.retainedArtifacts(),
        options.banishedDependencies(),
        currentModel.getDependencies(),
        options.trim().passThroughArtifacts(),
        List.of(),
        List.of());
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, options.session());
    try (AnalysisProjectionWorkspace workspace = AnalysisProjectionWorkspace.create()) {
      final AnalysisEnvironment operationEnvironment =
          environment.withProjectionDirectory(workspace.directory());
      final MavenAnalysisResolutionContext context =
          MavenAnalysisResolutionContext.forAnalyze(
              currentModel, project, options.session(), resolver, operationEnvironment);
      final AnalyzeBanPlan banPlan = AnalyzeBanPlan.create(context, options);
      final PreparedAnalysis prepared =
          MavenAnalysisPreparation.prepare(
              context.project(),
              options.withEnvironment(operationEnvironment),
              DependencyDynamicRoots::scan,
              context,
              banPlan);
      return AnalyzePrediction.from(ElisionReachabilityEngine.finishAnalysis(prepared));
    }
  }

  /* package */ PreparedAnalysis prepare(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return prepare(project, options, DependencyDynamicRoots::scan);
  }

  /* package */ PreparedAnalysis prepare(
      final MavenProject project,
      final AnalysisOptions options,
      final DynamicRootScanner dynamicRootScanner)
      throws IOException, MojoFailureException {
    return MavenAnalysisPreparation.prepare(project, options, dynamicRootScanner);
  }

  /* package */ Analysis finish(final PreparedAnalysis prepared)
      throws IOException, MojoFailureException {
    if (!prepared.options().trim().enabled()) {
      MavenArtifactInventory.verifyPreparedInventory(prepared);
    }
    if (ElisionReachabilityEngine.requiresTierAwareMrjarTrim(prepared)) {
      final Analysis analysis =
          ElisionReachabilityEngine.finishEffectiveOutputs(
              ElisionReachabilityEngine.finishAnalysis(prepared));
      final TrimOutputGenerationCommitHandle generation = analysis.trimResult().generationCommit();
      if (generation != null) {
        try (generation) {
          generation.commit();
          generation.cleanupCommitted();
        }
      }
      return analysis;
    }
    final AnalysisOptions options = prepared.options();
    final TrimResult trimResult =
        options.trim().enabled()
            ? MavenDependencyTrimmer.trim(
                TrimRequestFactory.fromPreparedAnalysis(
                    prepared,
                    prepared.rawDecision().retainedArtifacts(),
                    prepared.pruningRequiredClasses()))
            : TrimResult.empty();
    return new Analysis(
        ElisionAnalysisModel.artifactViews(prepared),
        prepared.rawDecision(),
        prepared.rawDecision(),
        ElisionAnalysisModel.evidence(prepared),
        trimResult,
        null,
        null,
        prepared
            .policyOptions()
            .withOperationFingerprint(prepared.graphBinding().operationFingerprint()));
  }

  /* package */ EffectiveAnalysis finishAnalysis(final PreparedAnalysis prepared)
      throws IOException, MojoFailureException {
    return ElisionReachabilityEngine.finishAnalysis(prepared);
  }

  /* package */ Analysis finishEffectiveOutputs(final EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return ElisionReachabilityEngine.finishEffectiveOutputs(effective);
  }
}
