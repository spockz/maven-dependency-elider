// WHY: Groups Elide configuration at the Maven boundary.
// The runner consumes this immutable handoff across both execution paths.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.IOException;
import java.util.List;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Immutable input assembled by ElideMojo for one goal execution. */
record MavenElideExecutionConfiguration(
    Lifecycle lifecycle, AnalysisOptions analysisOptions, Publication publication) {
  /** Maven state and lifecycle switches used by the execution coordinator. */
  /* default */ record Lifecycle(
      MavenProject project,
      MavenSession session,
      MojoExecution mojoExecution,
      ProjectDependenciesResolver resolver,
      boolean skip,
      boolean leafOnly,
      List<String> banishedDependencies) {}

  /** Output settings and callbacks shared by both execution paths. */
  /* default */ record Publication(
      MavenElisionOutputPublisher.ReportFiles files,
      Log log,
      PlanPublication planPublication,
      CacheConfig cacheConfig,
      ConfiguredVulnerabilityMappings vulnerabilityMappings,
      boolean preconditionProofEnabled,
      boolean assumeConventionalJavaSourceLayout,
      MavenElisionOutputPublisher.AfterStaging afterStaging,
      MavenElisionOutputPublisher.AfterStaging afterGenerationStaging) {}

  /** Installs the resolver plan after report and view staging succeeds. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  @FunctionalInterface
  interface PlanPublication {
    /** Publishes the verified graph projection after artifact views are applied. */
    void publish(
        MavenSession session,
        MavenProject project,
        List<io.github.spockz.elider.trimmer.ArtifactTrimRecord> trimRecords,
        ResolverArtifactGraphProjection graphProjection)
        throws IOException;
  }
}
