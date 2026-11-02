// WHY: Supplies concise legacy analysis presets for tests without production inheritance.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CompletenessOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.TrimOptions;
import java.io.File;
import java.util.List;
import org.apache.maven.execution.MavenSession;

/** Provides compact option presets for legacy service tests. */
final class MavenElisionTestOptions {
  private MavenElisionTestOptions() {}

  /* package */ static AnalysisOptions options(
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput) {
    return options(traceFiles, retainedArtifacts, productionOutput, null);
  }

  /* package */ static AnalysisOptions options(
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session) {
    return options(traceFiles, retainedArtifacts, productionOutput, session, false);
  }

  /* package */ static AnalysisOptions options(
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete) {
    return options(
        traceFiles,
        retainedArtifacts,
        productionOutput,
        session,
        sourceRootsComplete,
        false,
        List.of());
  }

  /* package */ static AnalysisOptions options(
      final List<File> traceFiles,
      final List<String> retainedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete,
      final boolean trimJars,
      final List<String> explicitTrimRoots) {
    return new AnalysisOptions(
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
        new DynamicRootOptions(true));
  }
}
