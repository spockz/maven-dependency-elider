/* WHY: Joins Maven evidence to trimming while keeping artifact pointer
 * changes outside analysis and staging. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.TrimGenerationPublisher.EffectiveOutputPlan;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates candidate analysis and output staging. */
public final class MavenDependencyTrimmer {
  /** Analyzes each implementation tier before trimming a multi-release archive. */
  /* package */ static final String MRJAR_VERTICAL_SHADING =
      MrjarStrategy.VERTICAL_SHADING.configurationValue();

  /** Preserves multi-release archives while still analyzing their dependencies. */
  /* package */ static final String MRJAR_PASS_THROUGH =
      MrjarStrategy.PASS_THROUGH.configurationValue();

  /** Trims modular dependencies as runtime derivatives by stripping module-info. */
  /* package */ static final String MRJAR_CLASSPATH_ONLY =
      MrjarStrategy.CLASSPATH_ONLY.configurationValue();

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
    return stageEffectiveOutputs(effective);
  }

  /* package */ static TrimResult stageEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return stageEffectiveOutputs(effective, null);
  }

  /* package */ static TrimResult stageEffectiveOutputs(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final TrimGenerationPublisher.OutputCheck outputCheck)
      throws IOException, MojoFailureException {
    final ElisionAnalysisModel.PreparedAnalysis prepared = effective.prepared();
    final ElisionAnalysisModel.AnalysisOptions options = prepared.options();
    final TrimRequest request =
        new TrimRequest(
            prepared.project(),
            options.session(),
            options.environment(),
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
                prepared.dynamicRootInputs().provenServiceInterfaces(),
                prepared.policyOptions().runtimePolicy()),
            new TrimPolicy(
                options.trim().explicitRoots(),
                options.trim().failOnUnsupportedMultiRelease(),
                options.trim().passThroughArtifacts(),
                options.trim().failOnUnsupportedModuleInfo(),
                options.trim().mrjarStrategy(),
                options.trim().enabled(),
                options.dynamicRoots().conservativeServiceLoaderRoots(),
                options.trim().workers(),
                options.trim().duplicateClasses()),
            options.trim().cacheProducerResolution().identity(),
            options.runtimePlatforms());
    final List<DuplicateClasses.ToleratedDuplicate> duplicates =
        DuplicateClasses.resolveRetained(request);
    final TrimExecutionEnvironment environment =
        reportedEnvironment(request, effective.trimAnalysis().analyzedTiers());
    if (!options.trim().enabled()) {
      if (outputCheck != null) {
        outputCheck.check(Map.of());
      }
      return TrimResult.empty(environment).withToleratedDuplicates(duplicates);
    }
    final EffectiveOutputPlan outputPlan = EffectiveOutputPlanFactory.create(effective);
    final JdkPlatformContext context =
        request.runtimePlatforms() == null
            ? MavenPlatformContextHolder.forOperation(request.session())
            : null;
    return EffectiveTrimOutput.trimEffectivePrepared(
            request,
            effective.trimAnalysis().targetRelease(),
            effective.trimAnalysis().runtimeRelease(),
            context,
            outputPlan,
            outputCheck)
        .withToleratedDuplicates(duplicates)
        .withExecutionEnvironment(environment);
  }

  /* package */ static TrimExecutionEnvironment executionEnvironment(final TrimRequest request)
      throws IOException {
    return executionEnvironment(
        request.project(),
        request.session(),
        request.environment(),
        request.policy().trimEnabled());
  }

  /* package */ static TrimExecutionEnvironment executionEnvironment(
      final MavenProject project,
      final MavenSession session,
      final AnalysisEnvironment environment,
      final boolean trimmingEnabled)
      throws IOException {
    final List<String> compilerOptions;
    if (environment == null) {
      compilerOptions =
          trimmingEnabled
              ? MavenCompilerSettings.platformReleaseOptions(project, session)
              : MavenCompilerSettings.analysisTargetOptions(project, session);
    } else {
      compilerOptions =
          trimmingEnabled
              ? MavenCompilerSettings.platformReleaseOptionsWithEnvironment(project, environment)
              : MavenCompilerSettings.analysisTargetOptions(project, environment);
    }
    return new TrimExecutionEnvironment(
        TrimPlatform.targetReleaseFromOptions(compilerOptions), Runtime.version().feature());
  }

  /* package */ static TrimExecutionEnvironment reportedEnvironment(
      final TrimRequest request, final List<Integer> analyzed) throws IOException {
    final TrimExecutionEnvironment releases = executionEnvironment(request);
    final MavenRuntimePlatforms platforms = request.runtimePlatforms();
    if (platforms == null) {
      return releases;
    }
    final List<String> compiler =
        request.environment() == null
            ? MavenCompilerSettings.analysisTargetOptions(request.project(), request.session())
            : MavenCompilerSettings.analysisTargetOptions(request.project(), request.environment());
    return new TrimExecutionEnvironment(
        releases.targetRelease(),
        releases.runtimeRelease(),
        MavenRuntimeCoverage.from(
            platforms, releases.targetRelease(), !compiler.isEmpty(), analyzed));
  }

  /* package */ static TrimAnalysisResult analyzeInMemory(
      final TrimRequest request,
      final Map<TrimArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    return MultiReleaseJarTrimmer.analyzeInMemory(request, discoveredRoots, forcedUnchanged);
  }
}
