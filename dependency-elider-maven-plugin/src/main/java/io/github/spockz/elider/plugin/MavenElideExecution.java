// WHY: Owns Elide's lifecycle and publication handoff outside the Mojo.
// Ban and ordinary analysis share the same ordered publication flow.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.EffectiveAnalysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.List;
import java.util.Map;
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
      if (configuration.analysisOptions().completeness().sourceRootsComplete()) {
        throw new MojoFailureException(
            "Dependency elision failed: elide.sourceRootsComplete is no longer supported; "
                + "bind elide to process-classes",
            new IOException("Obsolete source-root completeness setting"));
      }
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
    try {
      if (BanishedDependencyPolicy.normalize(configuration.lifecycle().banishedDependencies())
          .isEmpty()) {
        executeUnbannedAnalysis(configuration, service);
      } else {
        executeBannedAnalysis(configuration, service);
      }
    } catch (final ElisionReachabilityEngine.PlatformLinkageUnavailable unavailable) {
      final MavenElideExecutionConfiguration.Publication publication = configuration.publication();
      MavenForbiddenCodeAssessment.reportBlockedLinkage(
          unavailable,
          publication.vulnerabilityMappings(),
          publication.failOnForbiddenCode(),
          ForbiddenCodeAssessment.Mode.OBSERVED,
          publication.log());
      throw unavailable;
    }
  }

  private static void executeUnbannedAnalysis(
      final MavenElideExecutionConfiguration configuration, final MavenElisionService service)
      throws IOException, MojoFailureException {
    final MavenProject project = configuration.lifecycle().project();
    final PreparedAnalysis prepared = service.prepare(project, configuration.analysisOptions());
    final EffectiveAnalysis effective = service.finishAnalysis(prepared);
    finishAndPublish(configuration, service, effective, MavenBanPlan.empty(), null);
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
      plan.verifyAuditFresh(project, lifecycle.session());
      final EffectiveAnalysis effective = service.finishAnalysis(preparation.analysis());
      finishAndPublish(configuration, service, effective, plan, applicationBinding);
    }
  }

  private static void finishAndPublish(
      final MavenElideExecutionConfiguration configuration,
      final MavenElisionService service,
      final EffectiveAnalysis effective,
      final MavenBanPlan banPlan,
      final MavenArtifactViewBinding applicationBinding)
      throws IOException, MojoFailureException {
    final MavenElideExecutionConfiguration.Lifecycle lifecycle = configuration.lifecycle();
    final MavenElideExecutionConfiguration.Publication publication = configuration.publication();
    final ForbiddenCodeCheck check =
        publication.vulnerabilityMappings().forbiddenRules().isEmpty()
            ? null
            : new ForbiddenCodeCheck(effective, publication);
    final Analysis unboundAnalysis =
        ElisionReachabilityEngine.finishEffectiveOutputs(effective, check);
    publication.afterGenerationStaging().run(unboundAnalysis);
    final Analysis analysis =
        applicationBinding == null
            ? unboundAnalysis
            : applicationBinding.bindAnalysis(unboundAnalysis);
    final EliderTestViewPlan.Prepared testView =
        EliderTestViewPlan.prepare(
            lifecycle.session(),
            lifecycle.project(),
            banPlan.forcedAbsentAfterResolution(),
            MavenElisionReportWriter.outputPath(
                publication.files().summary(), lifecycle.project()));
    MavenElisionOutputPublisher.publish(
        new MavenElisionOutputPublisher.Request(
            lifecycle.project(),
            lifecycle.session(),
            service,
            analysis,
            publication.files(),
            publication.log(),
            publication.planPublication(),
            publication.cacheConfig(),
            publication.vulnerabilityMappings(),
            publication.snykConfiguration(),
            publication.preconditionProofEnabled(),
            publication.assumeConventionalJavaSourceLayout(),
            banPlan,
            applicationBinding,
            check == null ? List.of() : check.results()));
    if (testView != null) {
      EliderTestViewPlan.publish(lifecycle.session(), testView);
    }
  }

  @SuppressWarnings(
      "PMD.CommentRequired") // Carries one invocation's verified rows into publication.
  private static final class ForbiddenCodeCheck implements TrimGenerationPublisher.OutputCheck {
    private final EffectiveAnalysis effective;
    private final MavenElideExecutionConfiguration.Publication publication;
    private List<ForbiddenCodeAssessment> observations = List.of();

    private ForbiddenCodeCheck(
        final EffectiveAnalysis effective,
        final MavenElideExecutionConfiguration.Publication publication) {
      this.effective = effective;
      this.publication = publication;
    }

    private List<ForbiddenCodeAssessment> results() {
      return observations;
    }

    @Override
    public void check(
        final Map<
                io.github.spockz.elider.model.ArtifactCoordinate,
                TrimGenerationPublisher.StagedArchive>
            archives)
        throws IOException {
      observations =
          MavenForbiddenCodeAssessment.observe(
              effective,
              publication.vulnerabilityMappings(),
              publication.failOnForbiddenCode(),
              archives);
      MavenForbiddenCodeAssessment.enforce(observations, publication.log());
    }
  }
}
