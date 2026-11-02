// WHY: Shares strict ban planning and projection lifetime between Analyze and Elide.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ElisionAnalysisModel.AnalysisOptions;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.PreparedAnalysis;
import java.io.IOException;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectDependenciesResolver;

/** Prepares a strict ban plan and owns its temporary projection workspace. */
final class MavenBanPreparation implements AutoCloseable {
  /** Projection location kept alive until all generation rollback work has finished. */
  private final AnalysisProjectionWorkspace workspace;

  /** Resolver context bound to the isolated Maven model. */
  private final MavenAnalysisResolutionContext resolutionContext;

  /** Normalized ban plan checked against both dependency inventories. */
  private final MavenBanPlan banPlan;

  /** Prepared evidence and graph decisions consumed by the goal-specific finish step. */
  private final PreparedAnalysis preparedAnalysis;

  private MavenBanPreparation(
      final AnalysisProjectionWorkspace workspace,
      final MavenAnalysisResolutionContext context,
      final MavenBanPlan plan,
      final PreparedAnalysis analysis) {
    this.workspace = workspace;
    this.resolutionContext = context;
    this.banPlan = plan;
    this.preparedAnalysis = analysis;
  }

  @SuppressWarnings(
      "PMD.AvoidCatchingGenericException") // Unchecked failures must close the owned workspace.
  /* default */ static MavenBanPreparation prepare(
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
    final boolean bansRequested = !options.banishedDependencies().isEmpty();
    final boolean hookPresent =
        bansRequested && MavenOriginalInputAudit.hookPresent(options.session());
    if (bansRequested && !hookPresent && resolver == null) {
      throw new IOException("Detached Maven resolution requires a ProjectDependenciesResolver");
    }
    final MavenOriginalInputAudit.Inventory originalAudit =
        hookPresent ? MavenOriginalInputAudit.audit(project, options.session(), resolver) : null;
    final AnalysisEnvironment environment = AnalysisEnvironment.capture(project, options.session());
    final AnalysisProjectionWorkspace workspace = AnalysisProjectionWorkspace.create();
    try {
      final AnalysisEnvironment operationEnvironment =
          environment.withProjectionDirectory(workspace.directory());
      final AnalysisOptions operationOptions = options.withEnvironment(operationEnvironment);
      final MavenAnalysisResolutionContext context =
          MavenAnalysisResolutionContext.forOperation(
              currentModel, project, options.session(), resolver, operationEnvironment);
      final MavenBanPlan plan = MavenBanPlan.create(context, operationOptions, originalAudit);
      final PreparedAnalysis analysis =
          MavenAnalysisPreparation.prepare(
              context.project(), operationOptions, DependencyDynamicRoots::scan, context, plan);
      return new MavenBanPreparation(workspace, context, plan, analysis);
    } catch (final IOException | MojoFailureException | RuntimeException failure) {
      closeWorkspace(workspace, failure);
      throw failure;
    }
  }

  /* default */ MavenAnalysisResolutionContext context() {
    return resolutionContext;
  }

  /* default */ MavenBanPlan plan() {
    return banPlan;
  }

  /* default */ PreparedAnalysis analysis() {
    return preparedAnalysis;
  }

  @Override
  public void close() throws IOException {
    workspace.close();
  }

  private static void closeWorkspace(
      final AnalysisProjectionWorkspace workspace, final Throwable originalFailure) {
    try {
      workspace.close();
    } catch (final IOException cleanupFailure) {
      originalFailure.addSuppressed(cleanupFailure);
    }
  }
}
