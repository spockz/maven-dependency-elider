// WHY: Coordinates report, view, generation, and resolver-plan publication for one completed
// analysis.

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

/** Publishes all effective-analysis views through the goal's rollback boundary. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionOutputPublisher {
  private MavenElisionOutputPublisher() {
    throw new AssertionError("No instances");
  }

  static void publish(final Request request) throws IOException, MojoFailureException {
    MavenElisionOutputLogger.passThroughWarnings(request.log(), request.analysis());
    final MavenElisionService.ApplyPlan plan =
        request.service().plan(request.project(), request.analysis());
    final MavenElisionReportSnapshot reportSnapshot =
        MavenElisionReportSnapshot.from(request.project(), request.analysis());
    publishReportsAndViews(request, plan, reportSnapshot);
    MavenElisionOutputLogger.completion(request, reportSnapshot);
  }

  private static void publishReportsAndViews(
      final Request request,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionReportSnapshot reportSnapshot)
      throws IOException {
    final Path summary =
        MavenElisionReportWriter.outputPath(request.files().summary(), request.project());
    try (MavenOutputTransaction outputs =
        MavenOutputTransaction.forTargets(outputTargets(request.files(), summary))) {
      writeStagedReports(outputs, request, plan, reportSnapshot, summary);
      outputs.publish();
      publishViewsAndPlan(request, plan);
      commitBoth(outputs, request.generation());
      cleanupCommitted(outputs, request.generation());
    }
  }

  private static List<Path> outputTargets(final ReportFiles files, final Path summary) {
    final List<Path> targets = new ArrayList<>();
    targets.add(files.classUsage().toPath());
    targets.add(summary);
    if (files.trimJars()) {
      targets.add(files.sbom().toPath());
    }
    return targets;
  }

  private static void writeStagedReports(
      final MavenOutputTransaction outputs,
      final Request request,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionReportSnapshot reportSnapshot,
      final Path summary)
      throws IOException {
    final MavenElisionService.Analysis analysis = request.analysis();
    MavenClassUsageReportWriter.write(
        outputs.stagedPath(request.files().classUsage().toPath()),
        analysis.classUsageReport(),
        analysis.bytecodeScan());
    if (request.files().trimJars()) {
      MavenSbomWriter.write(
          request.project(), outputs.stagedPath(request.files().sbom().toPath()), plan, analysis);
    }
    MavenElisionReportWriter.write(outputs.stagedPath(summary), reportSnapshot);
  }

  @SuppressWarnings(
      "PMD.AvoidCatchingGenericException") // Project view rollback must include unchecked updater
  // failures.
  private static void publishViewsAndPlan(
      final Request request, final MavenElisionService.ApplyPlan plan) throws IOException {
    final MavenProject project = request.project();
    final Set<Artifact> originalArtifacts = project.getArtifacts();
    final Map<Artifact, File> originalFiles = originalArtifactFiles(plan);
    try {
      MavenArtifactViewUpdater.apply(plan, request.analysis().trimRecords());
      final Set<Artifact> retained = new LinkedHashSet<>(plan.resolvedArtifacts());
      project.setResolvedArtifacts(retained);
      project.setArtifacts(retained);
      request
          .planPublication()
          .publish(
              request.session(),
              project,
              request.analysis().trimRecords(),
              request.analysis().graphProjection());
    } catch (final IOException | RuntimeException failure) {
      restoreProjectViews(project, originalArtifacts, originalFiles);
      throw failure;
    }
  }

  @SuppressWarnings(
      "PMD.UseConcurrentHashMap") // Artifact file pointers must key by object identity.
  private static Map<Artifact, File> originalArtifactFiles(
      final MavenElisionService.ApplyPlan plan) {
    final Map<Artifact, File> result = new IdentityHashMap<>();
    plan.resolvedArtifacts().forEach(artifact -> result.put(artifact, artifact.getFile()));
    plan.directArtifacts().forEach(artifact -> result.putIfAbsent(artifact, artifact.getFile()));
    return result;
  }

  private static void restoreProjectViews(
      final MavenProject project,
      final Set<Artifact> originalArtifacts,
      final Map<Artifact, File> originalFiles) {
    originalFiles.forEach(Artifact::setFile);
    final Set<Artifact> restored = new LinkedHashSet<>(originalArtifacts);
    project.setResolvedArtifacts(restored);
    project.setArtifacts(restored);
  }

  private static void commitBoth(
      final MavenOutputTransaction outputs, final TrimOutputGenerationCommitHandle generation) {
    outputs.commit();
    if (generation != null) {
      generation.commit();
    }
  }

  private static void cleanupCommitted(
      final MavenOutputTransaction outputs, final TrimOutputGenerationCommitHandle generation)
      throws IOException {
    IOException cleanupFailure = null;
    try {
      outputs.cleanupCommitted();
    } catch (final IOException exception) {
      cleanupFailure = exception;
    }
    if (generation != null) {
      try {
        generation.cleanupCommitted();
      } catch (final IOException exception) {
        cleanupFailure = MavenOutputFileCleanup.append(cleanupFailure, exception);
      }
    }
    if (cleanupFailure != null) {
      throw new IOException("Publication committed, but backup cleanup failed", cleanupFailure);
    }
  }

  record ReportFiles(File classUsage, File sbom, File summary, boolean trimJars) {}

  record Request(
      MavenProject project,
      MavenSession session,
      MavenElisionService service,
      MavenElisionService.Analysis analysis,
      TrimOutputGenerationCommitHandle generation,
      ReportFiles files,
      Log log,
      ElideMojo.PlanPublication planPublication) {}
}
