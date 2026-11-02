/* WHY: Centralizes reflective field setup for AnalyzeMojo boundary tests. */

package io.github.spockz.elider.plugin;

import java.lang.reflect.Field;
import java.util.List;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.DefaultRepositorySystemSession;

/** Supports setup for plugin fields without public setters. */
final class AnalyzeMojoTestFieldSupport {
  private AnalyzeMojoTestFieldSupport() {
    // WHY: Static helpers need no test instance.
  }

  @SuppressWarnings("PMD.AvoidAccessibilityAlteration")
  /* package */ static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  /* package */ static void installLegacyPredictionFixture(final AnalyzeMojo mojo)
      throws ReflectiveOperationException {
    set(
        mojo,
        "predictionService",
        (AnalyzePredictionService)
            (project, options, resolver) -> {
              final ElisionAnalysisModel.Analysis analysis =
                  new MavenElisionService().analyze(project, options);
              final String fingerprint =
                  MavenElisionGraphBinding.sha256(List.of("test-prediction"));
              return new AnalyzePrediction(
                  MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
                  analysis.artifacts().resolvedSnapshots(),
                  List.copyOf(analysis.effectiveDecision().retainedArtifacts()),
                  List.copyOf(analysis.effectiveDecision().elidedArtifacts()),
                  List.of(),
                  analysis.evidence(),
                  fingerprint,
                  ResolvedArtifactInventoryFingerprint.fingerprint(
                      analysis.artifacts().resolvedSnapshots()),
                  analysis.policyIdentity().operationFingerprint());
            });
  }

  /* package */ static void seedSelectedBanCapture(
      final AnalyzeMojo mojo, final MavenProject project, final List<String> bans)
      throws ReflectiveOperationException {
    final Plugin plugin = new Plugin();
    plugin.setVersion("1.0.0");
    final MojoExecution execution = new MojoExecution(plugin, "analyze", "default-cli");
    set(execution, "source", MojoExecution.Source.CLI);
    set(mojo, "mojoExecution", execution);
    final BanishedDependencyOriginalModel model =
        BanishedDependencyOriginalModel.capture(
            project,
            List.of(
                new BanishedDependencyOriginalModel.ExecutionPolicy(
                    "default-cli", "analyze", "1.0.0", "cli", "CLI", bans)),
            bans);
    final BanishedDependencyCaptureStore store =
        BanishedDependencyCaptureStore.empty().withModel(model);
    final MavenSession session =
        new MavenSession(
            null, new DefaultRepositorySystemSession(), new DefaultMavenExecutionRequest(), null);
    session.setCurrentProject(project);
    set(mojo, "session", session);
    EliderPreparationState.sessionData(session)
        .set(BanishedDependencyLifecycleActivation.CAPTURE_STORE_KEY, null, store.toPayload());
  }
}
