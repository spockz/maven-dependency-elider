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
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates candidate analysis and output staging. */
final class MavenDependencyTrimmer {
  /** Analyzes each implementation tier before trimming a multi-release archive. */
  /* package */ static final String MRJAR_VERTICAL_SHADING = "vertical-shading";

  /** Preserves multi-release archives while still analyzing their dependencies. */
  /* package */ static final String MRJAR_PASS_THROUGH = "pass-through";

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

  /** Platform analysis uses the same JDK home as the Maven process. */
  /* package */ static final String JAVA_HOME_PROPERTY = "java.home";

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
      return TrimResult.empty();
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
    final MavenProject project = request.project();
    final List<String> compilerOptions =
        request.environment() == null
            ? MavenCompilerSettings.platformReleaseOptions(project, request.session())
            : MavenCompilerSettings.platformReleaseOptionsWithEnvironment(
                project, request.environment());
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int release = TrimPlatform.releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    verifyAnalysisPlatform(effective, release, runtimeRelease, javaHome);
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      return TrimOutputCoordinator.trimPrepared(
          request, release, runtimeRelease, context, outputPlan);
    }
  }

  /* package */ static TrimResult trim(final TrimRequest request)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final MavenSession session = request.session();
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(project, session);
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int release = TrimPlatform.releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    final JdkPlatformContext platformContext =
        MavenPlatformContextHolder.forOperation(session, javaHome);
    return TrimOutputCoordinator.trimPrepared(request, release, runtimeRelease, platformContext);
  }

  private static void verifyAnalysisPlatform(
      final ElisionAnalysisModel.EffectiveAnalysis effective,
      final int compilerRelease,
      final int runtimeRelease,
      final Path javaHome)
      throws IOException {
    final TrimAnalysisResult analysis = effective.trimAnalysis();
    if (compilerRelease != analysis.compilerRelease()
        || runtimeRelease != analysis.runtimeRelease()
        || !javaHome.toAbsolutePath().normalize().equals(analysis.javaHome())) {
      throw new IOException("Compiler or JDK context changed after effective analysis");
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
