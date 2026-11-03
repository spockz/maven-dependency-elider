/* WHY: Joins Maven evidence to trimming while keeping artifact pointer
 * changes outside analysis and staging. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates candidate analysis and output staging. */
final class MavenDependencyTrimmer {
  /** Analyzes each implementation tier before trimming a multi-release archive. */
  /* package */ static final String MRJAR_VERTICAL_SHADING = "vertical-shading";

  /** Preserves multi-release archives while still analyzing their dependencies. */
  /* package */ static final String MRJAR_PASS_THROUGH = "pass-through";

  /** Trims modular dependencies as runtime derivatives by stripping module descriptors. */
  /* package */ static final String MRJAR_CLASSPATH_ONLY = "classpath-only";

  /** Artifact type supported by archive trimming. */
  /* package */ static final String JAR_TYPE = "jar";

  /** Maven scopes whose archive classes can resolve retained program references. */
  /* package */ static final Set<String> ANALYSIS_LIBRARY_SCOPES =
      Set.of("compile", "runtime", "provided", "system");

  /** Cache schema used in the entry fingerprint and manifest envelope. */
  /* package */ static final int CACHE_SCHEMA_VERSION = 1;

  /** Domain marker distinguishes this cache from incompatible pre-release drafts. */
  /* package */ static final String CACHE_FORMAT_ID =
      "maven-dependency-elider-effective-output-cache";

  /** Default worker cap limits memory consumed by isolated candidate pools. */
  /* package */ static final int DEFAULT_TRIM_WORKERS = 4;

  /** A single worker preserves sequential operation for constrained builds. */
  /* package */ static final int MIN_TRIM_WORKERS = 1;

  private MavenDependencyTrimmer() {}

  /* package */ static TrimResult trimEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return trimEffectiveOutputs(effective, TrimOutputGenerationPublisher::atomicMove);
  }

  /* package */ static TrimResult trimEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final TrimOutputGenerationPublisher.MoveOperation move)
      throws IOException, MojoFailureException {
    final TrimResult result = stageEffectiveOutputs(effective, move);
    if (result.generationCommit() != null) {
      result.generationCommit().commit();
      result.generationCommit().cleanupCommitted();
    }
    return result;
  }

  /* package */ static TrimResult stageEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return stageEffectiveOutputs(effective, TrimOutputGenerationPublisher::atomicMove);
  }

  /* package */ static TrimResult stageEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final TrimOutputGenerationPublisher.MoveOperation move)
      throws IOException, MojoFailureException {
    final ElisionAnalysisModel.PreparedAnalysis prepared = effective.prepared();
    MavenArtifactInventory.verifyPreparedInventory(prepared);
    final ElisionAnalysisModel.AnalysisOptions options = prepared.options();
    if (!options.trim().enabled()) {
      return TrimResult.empty(
          new TrimExecutionEnvironment(
              effective.trimAnalysis().targetRelease(), effective.trimAnalysis().runtimeRelease()));
    }
    final TrimRequest request =
        new TrimRequest(
            prepared.project(),
            options.session(),
            prepared.resolvedSnapshots(),
            new TrimScanInputs(
                prepared.index(),
                prepared.dynamicRootInputs().scansByPath(),
                prepared.dynamicRootInputs().consumedInputs()),
            effective.effectiveDecision().retainedArtifacts(),
            new TrimEvidence(
                prepared.trace(),
                prepared.pruningRequiredClasses(),
                prepared
                    .bytecodeScan()
                    .map(BytecodeReferenceScan::referencedClasses)
                    .orElse(Set.of()),
                prepared.projectOutputClasses(),
                prepared.dynamicRootInputs().provenServiceInterfaces()),
            new TrimPolicy(
                options.trim().explicitRoots(),
                options.trim().failOnUnsupportedMultiRelease(),
                options.trim().passThroughArtifacts(),
                options.trim().failOnUnsupportedModuleInfo(),
                options.trim().mrjarStrategy(),
                options.trim().enabled(),
                options.dynamicRoots().conservativeServiceLoaderRoots(),
                options.trim().workers()),
            options.trim().cacheProducerResolution().identity());
    final Map<TrimArtifactRootKey, Set<String>> roots =
        TrimRootPlanner.artifactRootKeys(
            prepared.resolvedSnapshots(), effective.trimAnalysis().candidateRoots());
    final Set<ArtifactCoordinate> unchangedCoordinates =
        new LinkedHashSet<>(effective.forcedUnchangedCoordinates());
    unchangedCoordinates.addAll(
        classlessRetainedCoordinates(
            prepared.resolvedSnapshots(),
            prepared.index().classesByArtifact(),
            effective.effectiveDecision().retainedArtifacts()));
    final EffectiveOutputPlan outputPlan =
        new EffectiveOutputPlan(
            prepared,
            effective.trimAnalysis(),
            roots,
            unchangedCoordinates,
            effective.effectiveDecision().retainedArtifacts(),
            effective.inventoryFingerprint(),
            prepared.directInputFingerprint(),
            effective.operationFingerprint(),
            prepared.productionOutputFingerprint(),
            prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
            options.trim().explicitRoots(),
            options.trim().passThroughArtifacts(),
            options.completeness().sourceRootsComplete(),
            options.completeness().productionClassesComplete(),
            options.trim().mrjarStrategy(),
            options.trim().failOnUnsupportedModuleInfo(),
            move);
    final TrimExecutionEnvironment executionEnvironment = executionEnvironment(request);
    verifyAnalysisPlatform(effective, executionEnvironment);
    final JdkPlatformContext context = MavenPlatformContextHolder.forOperation(request.session());
    return TrimOutputCoordinator.trimPrepared(
        request,
        executionEnvironment.targetRelease(),
        executionEnvironment.runtimeRelease(),
        context,
        outputPlan);
  }

  /* package */ static TrimResult trim(final TrimRequest request)
      throws IOException, MojoFailureException {
    final TrimExecutionEnvironment executionEnvironment = executionEnvironment(request);
    final JdkPlatformContext platformContext =
        MavenPlatformContextHolder.forOperation(request.session());
    return TrimOutputCoordinator.trimPrepared(
        request,
        executionEnvironment.targetRelease(),
        executionEnvironment.runtimeRelease(),
        platformContext);
  }

  /* package */ static TrimExecutionEnvironment executionEnvironment(final TrimRequest request)
      throws IOException {
    final MavenProject project = request.project();
    final boolean trimmingEnabled = request.policy().trimEnabled();
    final List<String> compilerOptions;
    if (request.environment() == null) {
      compilerOptions =
          trimmingEnabled
              ? MavenCompilerSettings.platformReleaseOptions(project, request.session())
              : MavenCompilerSettings.analysisTargetOptions(project, request.session());
    } else {
      compilerOptions =
          trimmingEnabled
              ? MavenCompilerSettings.platformReleaseOptionsWithEnvironment(
                  project, request.environment())
              : MavenCompilerSettings.analysisTargetOptions(project, request.environment());
    }
    return new TrimExecutionEnvironment(
        TrimPlatform.targetReleaseFromOptions(compilerOptions), Runtime.version().feature());
  }

  private static void verifyAnalysisPlatform(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final TrimExecutionEnvironment executionEnvironment)
      throws IOException {
    final TrimAnalysisResult analysis = effective.trimAnalysis();
    if (executionEnvironment.targetRelease() != analysis.targetRelease()
        || executionEnvironment.runtimeRelease() != analysis.runtimeRelease()) {
      throw new IOException("Target or runtime release changed after effective analysis");
    }
  }

  private static Set<ArtifactCoordinate> classlessRetainedCoordinates(
      final List<ElisionAnalysisModel.ArtifactSnapshot> inventory,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact,
      final Set<ArtifactCoordinate> retained) {
    final Map<Path, Set<String>> byPath = TrimCandidatePlanner.classesByPath(classesByArtifact);
    return inventory.stream()
        .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
        .filter(snapshot -> retained.contains(snapshot.coordinate()))
        .filter(
            snapshot ->
                byPath
                    .getOrDefault(snapshot.filePath().toAbsolutePath().normalize(), Set.of())
                    .isEmpty())
        .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  /* package */ static TrimAnalysisResult analyzeInMemory(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    return MultiReleaseJarTrimmer.analyzeInMemory(request, discoveredRoots, forcedUnchanged);
  }
}
