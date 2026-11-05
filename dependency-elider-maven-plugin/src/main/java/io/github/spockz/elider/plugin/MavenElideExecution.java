// WHY: Owns Elide's lifecycle and publication handoff outside the Mojo.
// Both ban and ordinary analysis share the same transactional publisher boundary.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

/** Executes Elide using a frozen configuration assembled by its Mojo. */
final class MavenElideExecution {
  private MavenElideExecution() {
    throw new AssertionError("No instances");
  }

  /* default */ static void execute(
      final MavenElideExecutionConfiguration.Lifecycle lifecycle,
      final Log log,
      final Supplier<MavenElideExecutionConfiguration> configurationFactory)
      throws MojoFailureException {
    final MavenProject project = lifecycle.project();
    final MavenSession session = lifecycle.session();
    final MojoExecution mojoExecution = lifecycle.mojoExecution();
    LegacyRetentionSetting.rejectIfConfigured(project, session, mojoExecution);
    final String executionId = mojoExecution == null ? null : mojoExecution.getExecutionId();
    final String projectId = project == null ? null : project.getId();
    final MojoExecution.Source executionSource = EliderPreparationState.source(mojoExecution);
    if (EliderPreparationState.consumePreparedLifecycleDuplicate(
        session, executionId, projectId, executionSource)) {
      return;
    }
    try {
      if (shouldSkip(lifecycle, log, executionId, projectId, executionSource)) {
        return;
      }
      final MavenElideExecutionConfiguration configuration = configurationFactory.get();
      BanishedDependencyLifecycleActivation.verifyElideConfiguration(
          session, project, mojoExecution, lifecycle.banishedDependencies());
      executeAnalysis(configuration);
      EliderPreparationState.completeInjectedCliPreparation(
          session, executionId, projectId, executionSource);
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision failed: " + exception.getMessage(), exception);
    }
  }

  private static boolean shouldSkip(
      final MavenElideExecutionConfiguration.Lifecycle lifecycle,
      final Log log,
      final String executionId,
      final String projectId,
      final MojoExecution.Source executionSource)
      throws IOException {
    if (lifecycle.skip()) {
      publishEmptyPlan(lifecycle.session(), lifecycle.project());
      completePreparation(lifecycle.session(), executionId, projectId, executionSource);
      return true;
    }
    if (lifecycle.leafOnly()
        && ReactorLeafModuleDetector.isIntermediateReactorModule(
            lifecycle.project(), lifecycle.session())) {
      logIntermediateModule(log, lifecycle.project());
      publishEmptyPlan(lifecycle.session(), lifecycle.project());
      completePreparation(lifecycle.session(), executionId, projectId, executionSource);
      return true;
    }
    return false;
  }

  private static void logIntermediateModule(final Log log, final MavenProject project) {
    if (log.isInfoEnabled()) {
      log.info(
          "Skipping dependency elision on intermediate reactor module: "
              + (project == null ? "unknown" : project.getArtifactId()));
    }
  }

  private static void publishEmptyPlan(final MavenSession session, final MavenProject project)
      throws IOException {
    ResolverArtifactPlanPublisher.publish(session, project, List.of());
  }

  private static void completePreparation(
      final MavenSession session,
      final String executionId,
      final String projectId,
      final MojoExecution.Source executionSource) {
    EliderPreparationState.completeInjectedCliPreparation(
        session, executionId, projectId, executionSource);
  }

  private static void executeAnalysis(final MavenElideExecutionConfiguration configuration)
      throws IOException, MojoFailureException {
    final MavenElisionService service = new MavenElisionService();
    if (BanishedDependencyPolicy.normalize(configuration.lifecycle().banishedDependencies())
        .isEmpty()) {
      executeUnbannedAnalysis(configuration, service);
    } else {
      executeBannedAnalysis(configuration, service);
    }
  }

  private static void executeUnbannedAnalysis(
      final MavenElideExecutionConfiguration configuration, final MavenElisionService service)
      throws IOException, MojoFailureException {
    final MavenProject project = configuration.lifecycle().project();
    final PreparedAnalysis prepared = service.prepare(project, configuration.analysisOptions());
    final EffectiveAnalysis effective = service.finishAnalysis(prepared);
    final Analysis analysis = service.finishEffectiveOutputs(effective);
    try (TrimOutputGenerationCommitHandle generation = analysis.trimResult().generationCommit()) {
      publish(configuration, service, analysis, generation, MavenBanPlan.empty(), null);
    }
  }

  private static void executeBannedAnalysis(
      final MavenElideExecutionConfiguration configuration, final MavenElisionService service)
      throws IOException, MojoFailureException {
    final MavenElideExecutionConfiguration.Lifecycle lifecycle = configuration.lifecycle();
    final MavenProject project = lifecycle.project();
    final MavenAnalysisResolutionContext requestContext;
    final MavenArtifactViewBinding.LiveSnapshot liveSnapshot =
        MavenArtifactViewBinding.capture(project);
    try (MavenBanPreparation preparation =
        MavenBanPreparation.prepare(
            project, configuration.analysisOptions(), lifecycle.resolver())) {
      requestContext = preparation.context();
      final MavenBanPlan plan = preparation.plan();
      final MavenArtifactViewBinding applicationBinding =
          MavenArtifactViewBinding.bind(liveSnapshot, requestContext);
      applicationBinding.verifyFresh(project);
      plan.verifyAuditFresh(project, lifecycle.session());
      final EffectiveAnalysis effective = service.finishAnalysis(preparation.analysis());
      final Analysis unboundAnalysis = service.finishEffectiveOutputs(effective);
      try (TrimOutputGenerationCommitHandle generation =
          unboundAnalysis.trimResult().generationCommit()) {
        configuration.publication().afterGenerationStaging().run();
        applicationBinding.verifyFresh(project);
        plan.verifyAuditFresh(project, lifecycle.session());
        final Analysis analysis = applicationBinding.bindAnalysis(unboundAnalysis);
        publish(configuration, service, analysis, generation, plan, applicationBinding);
      }
    }
  }

  private static void publish(
      final MavenElideExecutionConfiguration configuration,
      final MavenElisionService service,
      final Analysis analysis,
      final TrimOutputGenerationCommitHandle generation,
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding applicationBinding)
      throws IOException, MojoFailureException {
    final MavenElideExecutionConfiguration.Lifecycle lifecycle = configuration.lifecycle();
    final MavenElideExecutionConfiguration.Publication publication = configuration.publication();
    MavenElisionOutputPublisher.publish(
        new MavenElisionOutputPublisher.Request(
            lifecycle.project(),
            lifecycle.session(),
            service,
            analysis,
            generation,
            publication.files(),
            publication.log(),
            publication.planPublication(),
            publication.cacheConfig(),
            publication.vulnerabilityMappings(),
            publication.preconditionProofEnabled(),
            publication.assumeConventionalJavaSourceLayout(),
            publication.afterStaging(),
            banPlan,
            applicationBinding));
  }
}
