// WHY: Coordinates report, view, generation, and resolver-plan publication for one completed
// analysis.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.project.MavenProject;

/** Publishes all effective-analysis views through the goal's rollback boundary. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TooManyMethods"
})
// Coordinates transactional subsystems behind one publication boundary.
final class MavenElisionOutputPublisher {
  private MavenElisionOutputPublisher() {
    throw new AssertionError("No instances");
  }

  static void publish(final Request request) throws IOException, MojoFailureException {
    MavenElisionOutputLogger.passThroughWarnings(request.log(), request.analysis());
    final MavenElisionService.ApplyPlan plan =
        request.service().plan(request.project(), request.analysis());
    final MavenVulnerabilityAssessment.Result assessment = publishReportsAndViews(request, plan);
    MavenElisionOutputLogger.completion(request, assessment);
  }

  private static MavenVulnerabilityAssessment.Result publishReportsAndViews(
      final Request request, final MavenElisionService.ApplyPlan plan) throws IOException {
    final Path summary =
        MavenElisionReportWriter.outputPath(request.files().summary(), request.project());
    final List<Path> outputTargets = outputTargets(request, summary);
    try (MavenOutputTransaction outputs = MavenOutputTransaction.forTargets(outputTargets)) {
      final List<ArtifactFileRef> baselineInventory = captureBaselineInventory(request);
      final MavenPreconditionInventory.Snapshot inventory =
          captureInventory(request, plan, outputTargets, outputs.stagingPaths());
      final MavenVulnerabilityAssessment.Result assessment = assess(request, inventory);
      final Optional<String> staleVexDigest = staleVexDigest(request, assessment);
      final MavenElisionReportSnapshot reportSnapshot =
          MavenElisionReportSnapshot.from(request.project(), request.analysis(), assessment);
      writeStagedReports(
          outputs,
          request,
          plan,
          reportSnapshot,
          summary,
          baselineInventory,
          inventory,
          assessment);
      final StagePlan stages = freezeStagedReports(outputs, request, assessment);
      request.afterStaging().run();
      outputs.verifyStageDigests(stages.digests());
      inventory.verifyFresh(
          request.project(),
          request.session(),
          plan,
          request.analysis(),
          outputTargets,
          stages.paths());
      cleanupStaleVex(request, assessment, staleVexDigest, outputs);
      outputs.publish(stages.digests());
      publishViewsAndPlan(request, plan);
      commitBoth(outputs, request.generation());
      cleanupCommitted(outputs, request.generation());
      return assessment;
    }
  }

  private static List<ArtifactFileRef> captureBaselineInventory(final Request request)
      throws IOException {
    if (!request.files().trimJars()) {
      return List.of();
    }
    return MavenSbomWriter.captureOriginalInventory(request.project());
  }

  private static MavenPreconditionInventory.Snapshot captureInventory(
      final Request request,
      final MavenElisionService.ApplyPlan plan,
      final List<Path> outputTargets,
      final List<Path> stages)
      throws IOException {
    return MavenPreconditionInventory.capture(
        request.project(),
        request.session(),
        plan,
        request.analysis(),
        request.preconditionProofEnabled(),
        outputTargets,
        stages);
  }

  private static MavenVulnerabilityAssessment.Result assess(
      final Request request, final MavenPreconditionInventory.Snapshot inventory)
      throws IOException {
    return new MavenVulnerabilityAssessment(request.log())
        .assess(
            request.cacheConfig(), request.vulnerabilityMappings(), request.analysis(), inventory);
  }

  private static Optional<String> staleVexDigest(
      final Request request, final MavenVulnerabilityAssessment.Result assessment) {
    if (!request.files().trimJars() || hasVex(assessment)) {
      return Optional.empty();
    }
    return unchangedOwnedVexDigest(request, false);
  }

  private static StagePlan freezeStagedReports(
      final MavenOutputTransaction outputs,
      final Request request,
      final MavenVulnerabilityAssessment.Result assessment)
      throws IOException {
    final List<Path> paths = installStages(outputs, request, assessment);
    final Map<Path, String> digests = outputs.captureStageDigests(paths);
    if (request.files().trimJars()) {
      final List<Path> generated =
          MavenGeneratedOutputs.generatedOutputPaths(
              request.project(),
              request.files().sbom(),
              request.files().baselineSbom(),
              request.files().vex(),
              hasVex(assessment));
      MavenGeneratedOutputManifest.validateStage(
          outputs.stagedPath(MavenGeneratedOutputs.manifestPath(request.project())),
          generated,
          digests);
      if (!hasVex(assessment)) {
        outputs.skipTarget(request.files().vex().toPath());
      }
    }
    return new StagePlan(paths, digests);
  }

  private static void cleanupStaleVex(
      final Request request,
      final MavenVulnerabilityAssessment.Result assessment,
      final Optional<String> originalDigest,
      final MavenOutputTransaction outputs)
      throws IOException {
    if (!request.files().trimJars() || hasVex(assessment)) {
      return;
    }
    final Optional<String> currentDigest = unchangedOwnedVexDigest(request, true);
    if (originalDigest.isPresent() && originalDigest.equals(currentDigest)) {
      outputs.deleteTarget(request.files().vex().toPath(), originalDigest.orElseThrow());
    }
  }

  private static List<Path> outputTargets(final Request request, final Path summary) {
    final ReportFiles files = request.files();
    final List<Path> targets = new ArrayList<>();
    targets.add(files.classUsage().toPath());
    targets.add(summary);
    if (files.trimJars()) {
      targets.add(files.sbom().toPath());
      targets.add(files.baselineSbom().toPath());
      targets.add(files.vex().toPath());
      targets.addAll(MavenSbomWriter.stagedPaths(request.project()));
      targets.add(MavenGeneratedOutputs.manifestPath(request.project()));
    }
    return targets;
  }

  private static void writeStagedReports(
      final MavenOutputTransaction outputs,
      final Request request,
      final MavenElisionService.ApplyPlan plan,
      final MavenElisionReportSnapshot reportSnapshot,
      final Path summary,
      final List<ArtifactFileRef> baselineInventory,
      final MavenPreconditionInventory.Snapshot inventory,
      final MavenVulnerabilityAssessment.Result assessment)
      throws IOException {
    final MavenElisionService.Analysis analysis = request.analysis();
    MavenClassUsageReportWriter.write(
        outputs.stagedPath(request.files().classUsage().toPath()),
        analysis.classUsageReport(),
        analysis.bytecodeScan());
    if (request.files().trimJars()) {
      final List<io.github.spockz.elider.model.VexAttestation> attestations =
          assessment.attestations();
      final Path sbom = outputs.stagedPath(request.files().sbom().toPath());
      MavenSbomWriter.write(
          request.project(), sbom, plan, analysis, attestations, inventory.artifactFiles());
      MavenSbomWriter.writeBaseline(
          request.project(),
          outputs.stagedPath(request.files().baselineSbom().toPath()),
          baselineInventory,
          analysis);
      if (hasVex(assessment)) {
        MavenSbomWriter.writeOpenVex(
            request.project(),
            outputs.stagedPath(request.files().vex().toPath()),
            plan,
            analysis,
            attestations,
            inventory.artifactFiles());
      }
      final List<Path> stagedSboms = MavenSbomWriter.stagedPaths(request.project());
      for (final Path stagedSbom : stagedSboms) {
        MavenSbomWriter.stage(sbom, outputs.stagedPath(stagedSbom));
      }
      final List<Path> generated =
          MavenGeneratedOutputs.generatedOutputPaths(
              request.project(),
              request.files().sbom(),
              request.files().baselineSbom(),
              request.files().vex(),
              hasVex(assessment));
      MavenGeneratedOutputManifest.writeStage(
          outputs.stagedPath(MavenGeneratedOutputs.manifestPath(request.project())),
          generated,
          stagedTargets(outputs, generated));
    }
    MavenElisionReportWriter.write(outputs.stagedPath(summary), reportSnapshot);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Stage lookup is synchronous and single-threaded.
  private static Map<Path, Path> stagedTargets(
      final MavenOutputTransaction outputs, final List<Path> generated) throws IOException {
    final Map<Path, Path> stages = new HashMap<>();
    for (final Path target : generated) {
      final Path normalized = target.toAbsolutePath().normalize();
      stages.put(normalized, outputs.stagedPath(normalized));
    }
    return stages;
  }

  private static List<Path> installStages(
      final MavenOutputTransaction outputs,
      final Request request,
      final MavenVulnerabilityAssessment.Result assessment)
      throws IOException {
    final List<Path> stages = new ArrayList<>(outputs.stagingPaths());
    if (request.files().trimJars() && !hasVex(assessment)) {
      stages.remove(outputs.stagedPath(request.files().vex().toPath()));
    }
    return List.copyOf(stages);
  }

  private static boolean hasVex(final MavenVulnerabilityAssessment.Result assessment) {
    return assessment != null && !assessment.attestations().isEmpty();
  }

  private static Optional<String> unchangedOwnedVexDigest(
      final Request request, final boolean logUnowned) {
    final Path target = request.files().vex().toPath().toAbsolutePath().normalize();
    try {
      final Optional<String> digest =
          MavenGeneratedOutputs.unchangedOwnedOutputDigest(request.project(), target);
      if (digest.isPresent()) {
        return digest;
      }
      if (logUnowned
          && request.log().isWarnEnabled()
          && !MavenPreconditionOutputState.definitelyAbsent(target)) {
        request
            .log()
            .warn(
                "Preserving OpenVEX output without matching generated-output ownership evidence: "
                    + target);
      }
    } catch (final IOException failure) {
      if (logUnowned && request.log().isWarnEnabled()) {
        request
            .log()
            .warn(
                "Preserving OpenVEX output because generated-output ownership could not be "
                    + "verified: "
                    + target
                    + " ("
                    + failure.getMessage()
                    + ")");
      }
    }
    return Optional.empty();
  }

  @SuppressWarnings(
      "PMD.AvoidCatchingGenericException") // Project view rollback must include unchecked updater
  // failures.
  private static void publishViewsAndPlan(
      final Request request, final MavenElisionService.ApplyPlan plan) throws IOException {
    final MavenProject project = request.project();
    final Set<Artifact> originalArtifacts = new LinkedHashSet<>(project.getArtifacts());
    final Set<Artifact> originalResolvedArtifacts = resolvedArtifactView(project);
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
      restoreProjectViews(project, originalArtifacts, originalResolvedArtifacts, originalFiles);
      throw failure;
    }
  }

  private static Set<Artifact> resolvedArtifactView(final MavenProject project) {
    final MavenProject snapshot = project.clone();
    snapshot.setArtifactFilter(artifact -> true);
    snapshot.setArtifacts(null);
    return new LinkedHashSet<>(snapshot.getArtifacts());
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
      final Set<Artifact> originalResolvedArtifacts,
      final Map<Artifact, File> originalFiles) {
    originalFiles.forEach(Artifact::setFile);
    project.setResolvedArtifacts(new LinkedHashSet<>(originalResolvedArtifacts));
    project.setArtifacts(new LinkedHashSet<>(originalArtifacts));
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

  record ReportFiles(
      File classUsage, File sbom, File baselineSbom, File vex, File summary, boolean trimJars) {}

  /** Hook used to mutate staged state in freshness tests. */
  @FunctionalInterface
  interface AfterStaging {
    /** Runs after stages are frozen and before integrity validation. */
    void run() throws IOException;
  }

  private record StagePlan(List<Path> paths, Map<Path, String> digests) {
    StagePlan {
      paths = List.copyOf(paths);
      digests = Map.copyOf(digests);
    }
  }

  record Request(
      MavenProject project,
      MavenSession session,
      MavenElisionService service,
      MavenElisionService.Analysis analysis,
      TrimOutputGenerationCommitHandle generation,
      ReportFiles files,
      Log log,
      ElideMojo.PlanPublication planPublication,
      CacheConfig cacheConfig,
      List<VulnerabilitySymbolMapping> vulnerabilityMappings,
      boolean preconditionProofEnabled,
      AfterStaging afterStaging) {
    Request {
      vulnerabilityMappings = List.copyOf(vulnerabilityMappings);
    }
  }
}
