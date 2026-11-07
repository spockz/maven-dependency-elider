// WHY: Coordinates report, view, generation, and resolver-plan publication for one completed
// analysis.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
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

/** Publishes effective analysis reports, Maven views, and the resolver plan. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.GodClass", "PMD.TooManyMethods"})
// Coordinates independent per-file outputs with the final Maven-view update.
final class MavenElisionOutputPublisher {
  private MavenElisionOutputPublisher() {
    throw new AssertionError("No instances");
  }

  static void publish(final Request request) throws IOException, MojoFailureException {
    if (request.banPlan().requested()) {
      if (request.applicationBinding() == null) {
        throw new MojoFailureException("Elide ban publication has no live Maven view binding");
      }
      request.banPlan().verifyContext(request.applicationBinding().resolutionContext());
      request.applicationBinding().verifyFresh(request.project());
      request.banPlan().verifyAuditFresh(request.project(), request.session());
    }
    MavenElisionOutputLogger.passThroughWarnings(request.log(), request.analysis());
    final ExclusionReview exclusionReview =
        ExclusionReview.capture(request.project(), request.session());
    final ElisionAnalysisModel.ApplyPlan plan =
        MavenArtifactInventory.plan(request.project(), request.analysis());
    if (request.banPlan().requested()) {
      MavenBanPublicationVerifier.verify(
          request.banPlan(), request.applicationBinding(), plan, request.analysis());
    }
    final MavenVulnerabilityAssessment.Result assessment =
        publishReportsAndViews(request, plan, exclusionReview);
    MavenElisionOutputLogger.completion(request, assessment, exclusionReview);
  }

  private static MavenVulnerabilityAssessment.Result publishReportsAndViews(
      final Request request,
      final ElisionAnalysisModel.ApplyPlan plan,
      final ExclusionReview exclusionReview)
      throws IOException, MojoFailureException {
    final Path summary =
        MavenElisionReportWriter.outputPath(request.files().summary(), request.project());
    final List<Path> outputTargets = outputTargets(request, summary);
    MavenOutputTargetValidation.validate(outputTargets);
    final List<ArtifactFileRef> baselineInventory = captureBaselineInventory(request);
    final MavenPreconditionInventory.Snapshot inventory = captureInventory(request, plan);
    final MavenVulnerabilityAssessment.Result assessment = assess(request, inventory);
    final Optional<String> staleVexDigest = staleVexDigest(request, assessment);
    final MavenElisionReportSnapshot reportSnapshot =
        MavenElisionReportSnapshot.from(request.project(), request.analysis(), assessment)
            .withExclusionReview(exclusionReview);
    writeReports(request, plan, reportSnapshot, summary, baselineInventory, inventory, assessment);
    cleanupStaleVex(request, assessment, staleVexDigest);
    if (request.files().trimJars()) {
      final List<Path> generated =
          MavenGeneratedOutputs.Paths.generatedOutputPaths(
              request.project(),
              request.files().sbom(),
              request.files().baselineSbom(),
              request.files().vex(),
              hasVex(assessment));
      MavenGeneratedOutputs.record(request.project(), generated);
    }
    publishViewsAndPlan(request, plan);
    return assessment;
  }

  private static List<ArtifactFileRef> captureBaselineInventory(final Request request)
      throws IOException {
    if (!request.files().trimJars()) {
      return List.of();
    }
    return MavenSbomWriter.captureOriginalInventory(request.project());
  }

  private static MavenPreconditionInventory.Snapshot captureInventory(
      final Request request, final ElisionAnalysisModel.ApplyPlan plan) throws IOException {
    return MavenPreconditionInventory.capture(
        request.project(),
        request.session(),
        plan,
        request.analysis(),
        request.preconditionProofEnabled());
  }

  private static MavenVulnerabilityAssessment.Result assess(
      final Request request, final MavenPreconditionInventory.Snapshot inventory)
      throws IOException {
    return new MavenVulnerabilityAssessment(
            request.log(), request.assumeConventionalJavaSourceLayout())
        .assess(
            request.cacheConfig(),
            request.vulnerabilityMappings(),
            request.analysis(),
            inventory,
            request.snykConfiguration());
  }

  private static Optional<String> staleVexDigest(
      final Request request, final MavenVulnerabilityAssessment.Result assessment) {
    if (!request.files().trimJars() || hasVex(assessment)) {
      return Optional.empty();
    }
    return unchangedOwnedVexDigest(request, true);
  }

  private static void cleanupStaleVex(
      final Request request,
      final MavenVulnerabilityAssessment.Result assessment,
      final Optional<String> originalDigest)
      throws IOException {
    if (!request.files().trimJars() || hasVex(assessment)) {
      return;
    }
    if (originalDigest.isPresent()) {
      java.nio.file.Files.deleteIfExists(request.files().vex().toPath());
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
      targets.addAll(MavenSbomWriter.embeddedSbomPaths(request.project()));
      targets.add(MavenGeneratedOutputs.Paths.manifestPath(request.project()));
      final Path buildDir =
          Path.of(request.project().getBuild().getDirectory()).toAbsolutePath().normalize();
      targets.add(buildDir.resolve(AdvisoryJdkModulesAnalyzer.ADVISORY_MODULES_FILENAME));
    }
    return targets;
  }

  private static void writeReports(
      final Request request,
      final ElisionAnalysisModel.ApplyPlan plan,
      final MavenElisionReportSnapshot reportSnapshot,
      final Path summary,
      final List<ArtifactFileRef> baselineInventory,
      final MavenPreconditionInventory.Snapshot inventory,
      final MavenVulnerabilityAssessment.Result assessment)
      throws IOException {
    final ElisionAnalysisModel.Analysis analysis = request.analysis();
    MavenClassUsageReportWriter.write(
        request.files().classUsage().toPath(),
        analysis.evidence().classUsageReport(),
        analysis.evidence().bytecodeScan(),
        null,
        reportSnapshot.exclusionReview());
    if (request.files().trimJars()) {
      final List<io.github.spockz.elider.model.VexAttestation> attestations =
          assessment.attestations();
      final Path sbom = request.files().sbom().toPath();
      MavenSbomWriter.write(
          request.project(), sbom, plan, analysis, attestations, inventory.artifactFiles());
      MavenSbomWriter.writeBaseline(
          request.project(), request.files().baselineSbom().toPath(), baselineInventory, analysis);
      if (hasVex(assessment)) {
        MavenSbomWriter.writeOpenVex(
            request.project(),
            request.files().vex().toPath(),
            plan,
            analysis,
            attestations,
            inventory.artifactFiles());
      }
      final List<Path> embeddedSboms = MavenSbomWriter.embeddedSbomPaths(request.project());
      for (final Path embeddedSbom : embeddedSboms) {
        MavenSbomWriter.writeEmbeddedSbom(sbom, embeddedSbom);
      }
      final Path advisoryModulesPath =
          Path.of(request.project().getBuild().getDirectory())
              .toAbsolutePath()
              .normalize()
              .resolve(AdvisoryJdkModulesAnalyzer.ADVISORY_MODULES_FILENAME);
      final List<Path> inputs = new ArrayList<>();
      final List<Path> classPath = new ArrayList<>();
      if (request.project().getBuild() != null
          && request.project().getBuild().getOutputDirectory() != null) {
        inputs.add(Path.of(request.project().getBuild().getOutputDirectory()));
      }
      SpringAotAssetPaths.resolveMainClasses(request.project()).ifPresent(inputs::add);
      for (final ArtifactFileRef ref : inventory.artifactFiles()) {
        if (ref.filePath().toString().endsWith(".jar")
            || ref.filePath().toString().endsWith(".class")) {
          classPath.add(ref.filePath());
        }
      }
      final Set<String> recommendedModules =
          new AdvisoryJdkModulesAnalyzer()
              .analyze(
                  inputs, classPath, analysis.trimResult().executionEnvironment().targetRelease());
      final String formattedModules =
          AdvisoryJdkModulesAnalyzer.formatModuleList(recommendedModules);
      MavenGeneratedOutputs.writeAtomically(
          advisoryModulesPath,
          temporary -> java.nio.file.Files.writeString(temporary, formattedModules));
    }
    MavenElisionReportWriter.write(summary, reportSnapshot);
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
      if (logUnowned && request.log().isWarnEnabled() && java.nio.file.Files.exists(target)) {
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
      "PMD.AvoidCatchingGenericException") // Restore Maven views after updater failures.
  private static void publishViewsAndPlan(
      final Request request, final ElisionAnalysisModel.ApplyPlan plan)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final Set<Artifact> originalArtifacts = new LinkedHashSet<>(project.getArtifacts());
    final Set<Artifact> originalResolvedArtifacts = resolvedArtifactView(project);
    final Map<Artifact, File> originalFiles = originalArtifactFiles(plan);
    try {
      if (request.banPlan().requested()) {
        request.applicationBinding().verifyFresh(project);
        request.banPlan().verifyAuditFresh(project, request.session());
      }
      MavenArtifactViewUpdater.apply(plan, request.analysis().trimResult().records());
      final Set<Artifact> retained = new LinkedHashSet<>(plan.resolvedArtifacts());
      project.setResolvedArtifacts(retained);
      project.setArtifacts(retained);
      request
          .planPublication()
          .publish(
              request.session(),
              project,
              request.analysis().trimResult().records(),
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
      final ElisionAnalysisModel.ApplyPlan plan) {
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

  record ReportFiles(
      File classUsage, File sbom, File baselineSbom, File vex, File summary, boolean trimJars) {}

  @SuppressWarnings("PMD.CommentRequired")
  @FunctionalInterface
  interface AfterGenerationStaging {
    /** Runs after trim generation completes and before final publication checks. */
    void run(ElisionAnalysisModel.Analysis analysis) throws IOException;
  }

  record Request(
      MavenProject project,
      MavenSession session,
      MavenElisionService service,
      ElisionAnalysisModel.Analysis analysis,
      ReportFiles files,
      Log log,
      MavenElideExecutionConfiguration.PlanPublication planPublication,
      CacheConfig cacheConfig,
      ConfiguredVulnerabilityMappings vulnerabilityMappings,
      SnykPackageIssuesIntegration.Configuration snykConfiguration,
      boolean preconditionProofEnabled,
      boolean assumeConventionalJavaSourceLayout,
      MavenBanPlan banPlan,
      MavenArtifactViewBinding applicationBinding) {
    Request {
      java.util.Objects.requireNonNull(vulnerabilityMappings, "vulnerabilityMappings");
      java.util.Objects.requireNonNull(snykConfiguration, "snykConfiguration");
      java.util.Objects.requireNonNull(banPlan, "banPlan");
    }
  }
}
