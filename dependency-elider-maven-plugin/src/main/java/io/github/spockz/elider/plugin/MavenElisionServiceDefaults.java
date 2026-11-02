// WHY: Keeps legacy Analyze presets outside the checked lifecycle coordinator.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.File;
import java.io.IOException;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/**
 * Builds supported Analyze option presets and delegates them to the service. Its implicit
 * constructor supports Maven mojo subclasses.
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
abstract class MavenElisionServiceDefaults {
  /* default */ final Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, retainedArtifacts, productionOutput, null, false);
  }

  /* default */ final Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, retainedArtifacts, productionOutput, session, false);
  }

  /* default */ final Analysis analyze(
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

  /* default */ final Analysis analyze(
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

  /* default */ abstract Analysis analyze(MavenProject project, AnalysisOptions options)
      throws IOException, MojoFailureException;
}
