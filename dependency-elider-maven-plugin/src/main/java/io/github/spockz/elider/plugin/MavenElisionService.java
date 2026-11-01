// WHY: Coordinates checked Maven analysis and trimming while collaborators own
// scanning and graph policy.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootScanner;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates shared trace analysis and a nonmutating Maven artifact plan. */
final class MavenElisionService {
  /** Declares the package-scoped constructor required for this stateless facade. */
  /* package */ MavenElisionService() {
    super();
  }

  /* package */ Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, retainedArtifacts, productionOutput, null, false);
  }

  /* package */ Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, retainedArtifacts, productionOutput, session, false);
  }

  /* package */ Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete)
      throws IOException, MojoFailureException {
    return analyze(
        project,
        traceFiles,
        retainedArtifacts,
        productionOutput,
        session,
        sourceRootsComplete,
        false,
        List.of());
  }

  /* package */ Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete,
      final boolean trimJars,
      final List<String> explicitTrimRoots)
      throws IOException, MojoFailureException {
    return analyze(
        project,
        new AnalysisOptions(
            traceFiles,
            retainedArtifacts,
            productionOutput,
            session,
            new CompletenessOptions(sourceRootsComplete, false, false, false),
            new TrimOptions(
                trimJars,
                explicitTrimRoots,
                false,
                List.of(),
                false,
                MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING),
            new DynamicRootOptions(true)));
  }

  /* package */ Analysis analyze(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return finish(prepare(project, options));
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
        null);
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
