// WHY: Adapts Maven artifacts into the shared pruning pipeline and prepares a checked plan.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.engine.DependencyPruner;
import io.github.spockz.elider.engine.PruneConfig;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.scanner.JarIndexScanner;
import io.github.spockz.elider.scanner.ProductionBytecodeReferenceScanner;
import io.github.spockz.elider.trace.CompositeTraceReader;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;

/** Coordinates shared trace analysis and a nonmutating Maven artifact plan. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.LawOfDemeter",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidDuplicateLiterals",
  "PMD.NPathComplexity",
  "PMD.ExcessiveParameterList"
})
final class MavenElisionService {
  /** Maven scopes that may be considered for whole-artifact elision. */
  private static final Set<String> ELIGIBLE_SCOPES = Set.of("compile", "runtime");

  /** Dependency scopes Maven can place on its production compile classpath. */
  private static final Set<String> COMPILE_VISIBLE_SCOPES = Set.of("compile", "provided", "system");

  record AnalysisOptions(
      List<File> traceFiles,
      List<String> excludedArtifacts,
      File productionOutput,
      MavenSession session,
      boolean sourceRootsComplete,
      boolean trimJars,
      List<String> explicitTrimRoots,
      boolean failOnUnsupportedMultiRelease,
      List<String> explicitPassThroughArtifacts,
      boolean failOnUnsupportedModuleInfo,
      boolean testResolutionContext,
      boolean conservativeServiceLoaderRoots,
      int trimWorkers) {
    AnalysisOptions {
      if (trimWorkers < MavenDependencyTrimmer.MIN_TRIM_WORKERS) {
        throw new IllegalArgumentException("trimWorkers must be at least 1");
      }
    }

    AnalysisOptions(
        final List<File> traceFiles,
        final List<String> excludedArtifacts,
        final File productionOutput,
        final MavenSession session,
        final boolean sourceRootsComplete,
        final boolean trimJars,
        final List<String> explicitTrimRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> explicitPassThroughArtifacts,
        final boolean failOnUnsupportedModuleInfo,
        final boolean testResolutionContext,
        final boolean conservativeServiceLoaderRoots) {
      this(
          traceFiles,
          excludedArtifacts,
          productionOutput,
          session,
          sourceRootsComplete,
          trimJars,
          explicitTrimRoots,
          failOnUnsupportedMultiRelease,
          explicitPassThroughArtifacts,
          failOnUnsupportedModuleInfo,
          testResolutionContext,
          conservativeServiceLoaderRoots,
          MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS);
    }

    AnalysisOptions(
        final List<File> traceFiles,
        final List<String> excludedArtifacts,
        final File productionOutput,
        final MavenSession session,
        final boolean sourceRootsComplete,
        final boolean trimJars,
        final List<String> explicitTrimRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> explicitPassThroughArtifacts,
        final boolean failOnUnsupportedModuleInfo,
        final boolean testResolutionContext) {
      this(
          traceFiles,
          excludedArtifacts,
          productionOutput,
          session,
          sourceRootsComplete,
          trimJars,
          explicitTrimRoots,
          failOnUnsupportedMultiRelease,
          explicitPassThroughArtifacts,
          failOnUnsupportedModuleInfo,
          testResolutionContext,
          true,
          MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS);
    }
  }

  /** Creates the stateless Maven adapter. */
  MavenElisionService() {
    super();
  }

  /** Analyzes the complete resolved set while scanning only real JAR artifacts. */
  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, excludedArtifacts, productionOutput, null, false);
  }

  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput,
      final MavenSession session)
      throws IOException, MojoFailureException {
    return analyze(project, traceFiles, excludedArtifacts, productionOutput, session, false);
  }

  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete)
      throws IOException, MojoFailureException {
    return analyze(
        project,
        traceFiles,
        excludedArtifacts,
        productionOutput,
        session,
        sourceRootsComplete,
        false,
        List.of());
  }

  Analysis analyze(
      final MavenProject project,
      final List<File> traceFiles,
      final List<String> excludedArtifacts,
      final File productionOutput,
      final MavenSession session,
      final boolean sourceRootsComplete,
      final boolean trimJars,
      final List<String> explicitTrimRoots)
      throws IOException, MojoFailureException {
    return analyze(
        project,
        new AnalysisOptions(
            traceFiles,
            excludedArtifacts,
            productionOutput,
            session,
            sourceRootsComplete,
            trimJars,
            explicitTrimRoots,
            false,
            List.of(),
            false,
            false));
  }

  Analysis analyze(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return finish(prepare(project, options));
  }

  PreparedAnalysis prepare(final MavenProject project, final AnalysisOptions options)
      throws IOException, MojoFailureException {
    return prepare(project, options, DependencyDynamicRoots::scan);
  }

  PreparedAnalysis prepare(
      final MavenProject project,
      final AnalysisOptions options,
      final DynamicRootScanner dynamicRootScanner)
      throws IOException, MojoFailureException {
    final List<File> traceFiles = options.traceFiles();
    final List<String> excludedArtifacts = options.excludedArtifacts();
    final File productionOutput = options.productionOutput();
    final MavenSession session = options.session();
    final boolean sourceRootsComplete = options.sourceRootsComplete();
    final boolean trimJars = options.trimJars();
    final List<String> explicitTrimRoots = options.explicitTrimRoots();
    final List<String> explicitPassThroughArtifacts = options.explicitPassThroughArtifacts();
    final List<Artifact> resolved = new ArrayList<>(project.getArtifacts());
    final List<ArtifactSnapshot> resolvedSnapshots = snapshots(resolved);
    validateIdentityPaths(resolvedSnapshots);
    final String inputFingerprint =
        ResolvedArtifactInventoryFingerprint.fingerprint(resolvedSnapshots);
    final Set<Artifact> directView = project.getDependencyArtifacts();
    final boolean directPresent = directView != null;
    final List<Artifact> direct = directPresent ? new ArrayList<>(directView) : List.of();
    final List<ArtifactSnapshot> directSnapshots = snapshots(direct);
    validateIdentityPaths(directSnapshots);
    final String directInputFingerprint =
        directPresent
            ? ResolvedArtifactInventoryFingerprint.fingerprint(directSnapshots)
            : "missing";
    final List<ArtifactFileRef> scanCandidates = new ArrayList<>();
    for (final ArtifactSnapshot snapshot : resolvedSnapshots) {
      if (isJarCandidate(snapshot)) {
        scanCandidates.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
    }
    final TraceData trace = new CompositeTraceReader().readAll(toPaths(traceFiles));
    final ArtifactClassIndex index = new JarIndexScanner().scan(scanCandidates);
    final CompilerInputs compilerInputs =
        compilerInputs(project, session, scanCandidates, index, sourceRootsComplete);
    final ProductionBytecodeInputs productionInputs = productionBytecodeInputs(productionOutput);
    final Set<String> provenServiceInterfaces = new HashSet<>();
    if (productionOutput != null && productionOutput.isDirectory()) {
      provenServiceInterfaces.addAll(
          new io.github.spockz.elider.scanner.ServiceLoaderCallScanner()
              .scan(productionOutput.toPath())
              .provenServiceInterfaces());
    }
    final DynamicRootInputs dynamicRootInputs =
        dynamicRoots(
            scanCandidates,
            dynamicRootScanner,
            provenServiceInterfaces,
            options.conservativeServiceLoaderRoots());
    final Set<String> pruningRequiredClasses =
        requiredClassesForTrimming(
            compilerInputs.requiredClasses(),
            dynamicRootInputs.classNames(),
            explicitTrimRoots,
            index,
            trimJars);
    final Set<ArtifactCoordinate> keepForPruning =
        new HashSet<>(compilerInputs.compileVisibleCoordinates());
    keepForPruning.addAll(dynamicRootInputs.declaringArtifacts());
    keepForPruning.addAll(dynamicRootArtifactOwners(dynamicRootInputs, index, scanCandidates));
    if (trimJars) {
      keepForPruning.addAll(
          parsePassThroughCoordinates(explicitPassThroughArtifacts, resolvedSnapshots));
    }
    final String productionOutputFingerprint = productionInputs.fingerprint();
    final Optional<BytecodeReferenceScan> bytecodeScan = productionInputs.scan();
    final Set<String> projectOutputClasses = new HashSet<>(compilerInputs.declaredClasses());
    if (bytecodeScan.isPresent()) {
      projectOutputClasses.addAll(classNamesInOutput(bytecodeScan.orElseThrow().scope()));
    }
    final ClassUsageReport classUsageReport = ClassUsageReport.classify(index, trace, bytecodeScan);
    verifyProjectInventory(project, directPresent, inputFingerprint, directInputFingerprint);
    MavenElisionGraphBinding.verifyInventoryFingerprint(resolvedSnapshots, inputFingerprint);
    final ElisionDecision jarDecision =
        new DependencyPruner()
            .prune(
                scanCandidates,
                index,
                trace,
                config(excludedArtifacts, keepForPruning),
                pruningRequiredClasses);
    final ElisionDecision decision = retainNonJarArtifacts(jarDecision, resolvedSnapshots);
    final MavenElisionGraphBinding.Result graphBinding =
        MavenElisionGraphBinding.bind(
            project, options, resolvedSnapshots, decision, trace, pruningRequiredClasses);
    MavenElisionGraphBinding.verifyInventoryFingerprint(
        resolvedSnapshots, graphBinding.inventoryFingerprint());
    if (!inputFingerprint.equals(graphBinding.inventoryFingerprint())) {
      throw new IOException("Resolved artifact inventory changed during analysis preparation");
    }
    verifyProjectInventory(project, directPresent, inputFingerprint, directInputFingerprint);
    return new PreparedAnalysis(
        project,
        options,
        resolvedSnapshots,
        directPresent,
        directSnapshots,
        decision,
        classUsageReport,
        bytecodeScan,
        scanCandidates,
        trace,
        index,
        dynamicRootInputs,
        projectOutputClasses,
        compilerInputs.requiredClasses(),
        pruningRequiredClasses,
        productionOutputFingerprint,
        inputFingerprint,
        directInputFingerprint,
        graphBinding);
  }

  Analysis finish(final PreparedAnalysis prepared) throws IOException, MojoFailureException {
    final MavenProject project = prepared.project();
    final AnalysisOptions options = prepared.options();
    final MavenSession session = options.session();
    final boolean trimJars = options.trimJars();
    final List<String> explicitTrimRoots = options.explicitTrimRoots();
    final boolean failOnUnsupportedMultiRelease = options.failOnUnsupportedMultiRelease();
    final List<String> explicitPassThroughArtifacts = options.explicitPassThroughArtifacts();
    final boolean failOnUnsupportedModuleInfo = options.failOnUnsupportedModuleInfo();
    final MavenDependencyTrimmer.TrimResult trimResult =
        trimJars
            ? MavenDependencyTrimmer.trim(
                new MavenDependencyTrimmer.TrimRequest(
                    project,
                    session,
                    prepared.resolvedSnapshots(),
                    new MavenDependencyTrimmer.ScanInputs(
                        prepared.index(), prepared.dynamicRootInputs().scansByPath()),
                    new HashSet<>(prepared.rawDecision().retainedArtifacts()),
                    prepared.trace(),
                    prepared.pruningRequiredClasses(),
                    prepared
                        .bytecodeScan()
                        .map(BytecodeReferenceScan::referencedClasses)
                        .orElse(Set.of()),
                    prepared.projectOutputClasses(),
                    explicitTrimRoots,
                    failOnUnsupportedMultiRelease,
                    explicitPassThroughArtifacts,
                    failOnUnsupportedModuleInfo,
                    prepared.dynamicRootInputs().provenServiceInterfaces(),
                    options.conservativeServiceLoaderRoots(),
                    options.trimWorkers()))
            : new MavenDependencyTrimmer.TrimResult(
                List.of(), List.of(), List.of(), List.of(), 0, 0L, 0);
    return new Analysis(
        prepared.resolvedSnapshots(),
        prepared.directArtifactsPresent(),
        prepared.directSnapshots(),
        prepared.rawDecision(),
        prepared.classUsageReport(),
        prepared.bytecodeScan(),
        trimResult.records(),
        trimResult.multiReleasePassthroughArtifacts(),
        trimResult.moduleInfoPassthroughArtifacts(),
        trimResult.configuredPassThroughArtifacts(),
        trimResult.cacheHits(),
        trimResult.maximumCacheHitNanos(),
        trimResult.analysisRuns(),
        prepared.dynamicRootInputs().unprovenServiceRootsByCoordinate());
  }

  EffectiveAnalysis finishAnalysis(final PreparedAnalysis prepared)
      throws IOException, MojoFailureException {
    final ElisionDecision rawDecision = prepared.rawDecision();
    final MavenElisionGraphBinding.Result binding = prepared.graphBinding();
    if (!prepared.inputFingerprint().equals(binding.inventoryFingerprint())) {
      throw new IOException("Graph binding does not match the prepared artifact inventory");
    }
    EffectiveGraphPolicy.Evaluation evaluation = binding.evaluation();
    ElisionDecision policyInput = rawDecision;
    ElisionDecision effectiveDecision = evaluation.effectiveDecision(rawDecision);
    final Set<ArtifactCoordinate> forcedUnchanged = new LinkedHashSet<>();
    addUnchangedPolicyArtifacts(evaluation, forcedUnchanged);
    if (!prepared.options().trimJars()) {
      forcedUnchanged.addAll(effectiveDecision.retainedArtifacts());
    }
    Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> discoveredRoots = Map.of();
    MavenDependencyTrimmer.InMemoryAnalysis analysis;
    while (true) {
      verifyPreparedInventory(prepared);
      final MavenDependencyTrimmer.TrimRequest trimRequest =
          trimRequest(prepared, effectiveDecision);
      analysis =
          MavenDependencyTrimmer.analyzeInMemory(trimRequest, discoveredRoots, forcedUnchanged);
      verifyPreparedInventory(prepared);
      final Set<ArtifactCoordinate> newlyReachedDrops =
          newlyReachedDrops(analysis, effectiveDecision);
      if (newlyReachedDrops.isEmpty()) {
        return new EffectiveAnalysis(
            prepared,
            evaluation,
            rawDecision,
            effectiveDecision,
            forcedUnchanged,
            analysis,
            binding.inventoryFingerprint(),
            binding.operationFingerprint(),
            binding.pair() == null || evaluation.failClosed()
                ? null
                : ResolverArtifactGraphProjection.create(
                    binding.pair(), evaluation.nodeDispositions()));
      }
      if (binding.pair() == null) {
        throw new IOException("Reachability found a raw drop without a bound graph pair");
      }
      policyInput = promoteForBytecode(policyInput, newlyReachedDrops);
      evaluation = EffectiveGraphPolicy.evaluatePair(binding.pair(), policyInput);
      effectiveDecision = evaluation.effectiveDecision(rawDecision);
      forcedUnchanged.addAll(newlyReachedDrops);
      addUnchangedPolicyArtifacts(evaluation, forcedUnchanged);
      discoveredRoots = discoveredRoots(prepared.resolvedSnapshots(), analysis.candidateRoots());
    }
  }

  @SuppressWarnings(
      "PMD.AvoidCatchingGenericException") // Restore the generation for any report-construction
  // failure.
  Analysis finishEffectiveOutputs(final EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    final MavenDependencyTrimmer.TrimResult trimResult =
        MavenDependencyTrimmer.stageEffectiveOutputs(effective);
    try {
      final PreparedAnalysis prepared = effective.prepared();
      final MediatedGraphReport mediatedGraph =
          MediatedGraphReport.create(
              prepared.graphBinding().pair(),
              effective.graphEvaluation(),
              effective.effectiveDecision().elidedArtifacts(),
              trimResult.records(),
              prepared.project().getGroupId()
                  + ":"
                  + prepared.project().getArtifactId()
                  + ":"
                  + prepared.project().getVersion());
      return new Analysis(
          prepared.resolvedSnapshots(),
          prepared.directArtifactsPresent(),
          prepared.directSnapshots(),
          effective.rawDecision(),
          effective.effectiveDecision(),
          prepared.classUsageReport(),
          prepared.bytecodeScan(),
          trimResult.records(),
          trimResult.multiReleasePassthroughArtifacts(),
          trimResult.moduleInfoPassthroughArtifacts(),
          trimResult.configuredPassThroughArtifacts(),
          trimResult.cacheHits(),
          trimResult.maximumCacheHitNanos(),
          trimResult.analysisRuns(),
          effective.graphProjection(),
          trimResult.generationCommit(),
          mediatedGraph,
          prepared.dynamicRootInputs().unprovenServiceRootsByCoordinate());
    } catch (final IOException | RuntimeException failure) {
      closeGenerationAfterFailure(trimResult.generationCommit(), failure);
      throw failure;
    }
  }

  private static void closeGenerationAfterFailure(
      final TrimOutputGenerationCommitHandle generationCommit, final Throwable failure) {
    if (generationCommit == null) {
      return;
    }
    try {
      generationCommit.close();
    } catch (final IOException cleanupFailure) {
      failure.addSuppressed(cleanupFailure);
    }
  }

  static void verifyPreparedInventory(final PreparedAnalysis prepared) throws IOException {
    verifyProjectInventory(
        prepared.project(),
        prepared.directArtifactsPresent(),
        prepared.inputFingerprint(),
        prepared.directInputFingerprint());
  }

  private static void verifyProjectInventory(
      final MavenProject project,
      final boolean directPresent,
      final String expectedResolvedFingerprint,
      final String expectedDirectFingerprint)
      throws IOException {
    final List<ArtifactSnapshot> resolvedSnapshots =
        snapshots(new ArrayList<>(project.getArtifacts()));
    if (!expectedResolvedFingerprint.equals(
        ResolvedArtifactInventoryFingerprint.fingerprint(resolvedSnapshots))) {
      throw new IOException("Live Maven resolved artifact view changed during analysis");
    }
    final Set<Artifact> directView = project.getDependencyArtifacts();
    if (directView != null != directPresent) {
      throw new IOException("Live Maven direct artifact view presence changed during analysis");
    }
    if (directPresent) {
      final List<ArtifactSnapshot> directSnapshots = snapshots(new ArrayList<>(directView));
      if (!expectedDirectFingerprint.equals(
          ResolvedArtifactInventoryFingerprint.fingerprint(directSnapshots))) {
        throw new IOException("Live Maven direct artifact view changed during analysis");
      }
    }
  }

  private static MavenDependencyTrimmer.TrimRequest trimRequest(
      final PreparedAnalysis prepared, final ElisionDecision effectiveDecision) {
    final AnalysisOptions options = prepared.options();
    return new MavenDependencyTrimmer.TrimRequest(
        prepared.project(),
        options.session(),
        prepared.resolvedSnapshots(),
        new MavenDependencyTrimmer.ScanInputs(
            prepared.index(), prepared.dynamicRootInputs().scansByPath()),
        new HashSet<>(effectiveDecision.retainedArtifacts()),
        prepared.trace(),
        prepared.sourceRequiredClasses(),
        prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
        prepared.projectOutputClasses(),
        options.explicitTrimRoots(),
        options.failOnUnsupportedMultiRelease(),
        options.explicitPassThroughArtifacts(),
        options.failOnUnsupportedModuleInfo(),
        prepared.dynamicRootInputs().provenServiceInterfaces(),
        options.conservativeServiceLoaderRoots(),
        options.trimWorkers());
  }

  private static void addUnchangedPolicyArtifacts(
      final EffectiveGraphPolicy.Evaluation evaluation, final Set<ArtifactCoordinate> unchanged) {
    unchanged.addAll(evaluation.ancestorPromotedArtifacts());
    unchanged.addAll(evaluation.protectedReasons().keySet());
  }

  private static ElisionDecision promoteForBytecode(
      final ElisionDecision decision, final Set<ArtifactCoordinate> promoted) {
    final Set<ArtifactCoordinate> retained = new LinkedHashSet<>(decision.retainedArtifacts());
    final Set<ArtifactCoordinate> elided = new LinkedHashSet<>(decision.elidedArtifacts());
    promoted.stream().filter(elided::remove).forEach(retained::add);
    return new ElisionDecision(
        retained,
        elided,
        decision.retainedClassesPerArtifact(),
        decision.unusedClassesPerArtifact(),
        decision.elapsedNanos());
  }

  /** These maps are local to one analysis invocation and not shared. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> discoveredRoots(
      final List<ArtifactSnapshot> snapshots, final Map<ArtifactCoordinate, Set<String>> roots)
      throws IOException {
    final Map<ArtifactCoordinate, ArtifactSnapshot> snapshotsByCoordinate = new HashMap<>();
    snapshots.forEach(snapshot -> snapshotsByCoordinate.put(snapshot.coordinate(), snapshot));
    final Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> result = new HashMap<>();
    for (final Map.Entry<ArtifactCoordinate, Set<String>> entry : roots.entrySet()) {
      result.put(artifactRootKey(snapshotsByCoordinate, entry.getKey()), entry.getValue());
    }
    return Map.copyOf(result);
  }

  private static MavenDependencyTrimmer.ArtifactRootKey artifactRootKey(
      final Map<ArtifactCoordinate, ArtifactSnapshot> snapshotsByCoordinate,
      final ArtifactCoordinate coordinate)
      throws IOException {
    final ArtifactSnapshot snapshot = snapshotsByCoordinate.get(coordinate);
    if (snapshot == null || snapshot.filePath() == null) {
      throw new IOException("Discovered roots have no artifact file: " + coordinate);
    }
    return new MavenDependencyTrimmer.ArtifactRootKey(
        snapshot.coordinate(),
        snapshot.filePath(),
        ArtifactDigests.read(snapshot.filePath()).sha256());
  }

  private static Set<ArtifactCoordinate> newlyReachedDrops(
      final MavenDependencyTrimmer.InMemoryAnalysis analysis,
      final ElisionDecision effectiveDecision) {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>(analysis.reachableArtifacts());
    result.retainAll(effectiveDecision.elidedArtifacts());
    return result;
  }

  /** Prepares Maven artifact views without mutating project state. */
  ApplyPlan plan(final MavenProject project, final Analysis analysis) throws IOException {
    final Set<ArtifactIdentity> elided = identities(analysis.effectiveDecision().elidedArtifacts());
    final Set<ArtifactIdentity> retained =
        identities(analysis.effectiveDecision().retainedArtifacts());
    retained.retainAll(elided);
    if (!retained.isEmpty()) {
      throw new IOException("Contradictory retained and elided artifact identities: " + retained);
    }
    final CurrentViews currentViews = verifyCurrentViews(project, analysis);
    return new ApplyPlan(
        retained(currentViews.resolvedArtifacts(), elided),
        analysis.directArtifactsPresent(),
        new LinkedHashSet<>(currentViews.directArtifacts()));
  }

  static CurrentViews verifyCurrentViews(final MavenProject project, final Analysis analysis)
      throws IOException {
    final List<Artifact> resolvedInput = new ArrayList<>(project.getArtifacts());
    validateCurrentView("resolved", resolvedInput, analysis.resolvedSnapshots());
    final Set<Artifact> directSet = project.getDependencyArtifacts();
    final boolean directViewPresent = directSet != null;
    if (directViewPresent != analysis.directArtifactsPresent()) {
      throw new IOException("Maven direct artifact view presence changed after analysis");
    }
    final List<Artifact> directInput = directSet == null ? List.of() : new ArrayList<>(directSet);
    validateCurrentView("direct", directInput, analysis.directSnapshots());
    validateIdentityPaths(analysis.resolvedSnapshots());
    validateIdentityPaths(analysis.directSnapshots());
    validateDirectPaths(analysis.resolvedSnapshots(), analysis.directSnapshots());
    return new CurrentViews(resolvedInput, directInput);
  }

  static List<ArtifactSnapshot> snapshots(final Collection<Artifact> artifacts) {
    return artifacts.stream().map(ArtifactSnapshot::from).toList();
  }

  @SuppressWarnings({
    "PMD.CyclomaticComplexity",
    "PMD.AvoidDuplicateLiterals",
    "PMD.CompareObjectsWithEquals"
  })
  private static void validateCurrentView(
      final String viewName, final List<Artifact> current, final List<ArtifactSnapshot> snapshots)
      throws IOException {
    if (current.size() != snapshots.size()) {
      throw new IOException("Maven " + viewName + " artifact view size changed after analysis");
    }
    for (int index = 0; index < current.size(); index++) {
      final Artifact artifact = current.get(index);
      final ArtifactSnapshot snapshot = snapshots.get(index);
      if (artifact != snapshot.artifact()) {
        throw new IOException(
            "Maven " + viewName + " artifact order or reference changed after analysis");
      }
      if (!snapshot.coordinate().equals(toCoordinate(artifact))) {
        throw new IOException("Maven " + viewName + " artifact coordinate changed after analysis");
      }
      if (!java.util.Objects.equals(snapshot.filePath(), normalizedPath(artifact))) {
        throw new IOException("Maven " + viewName + " artifact file path changed after analysis");
      }
    }
  }

  private static Path normalizedPath(final Artifact artifact) {
    final File file = artifact.getFile();
    return file == null ? null : file.toPath().toAbsolutePath().normalize();
  }

  private static boolean isJarCandidate(final ArtifactSnapshot snapshot) throws IOException {
    if (!"jar".equals(snapshot.coordinate().type())) {
      return false;
    }
    final Path file = snapshot.filePath();
    if (file == null) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    final Path fileName = file.getFileName();
    if (fileName == null || !Files.isRegularFile(file)) {
      throw new IOException("Resolved artifact has no regular file: " + snapshot.coordinate());
    }
    return fileName.toString().endsWith(".jar");
  }

  static boolean isJarCandidate(final Artifact artifact) throws IOException {
    return isJarCandidate(ArtifactSnapshot.from(artifact));
  }

  static ArtifactCoordinate toCoordinate(final Artifact artifact) {
    return new ArtifactCoordinate(
        artifact.getGroupId(),
        artifact.getArtifactId(),
        artifact.getVersion(),
        artifact.getType(),
        artifact.getClassifier(),
        artifact.getScope());
  }

  private static PruneConfig config(
      final List<String> excludedArtifacts, final Set<ArtifactCoordinate> keepArtifacts)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> exclusions = new LinkedHashSet<>();
    if (excludedArtifacts != null) {
      for (final String text : excludedArtifacts) {
        exclusions.add(parseExclusion(text));
      }
    }
    return new PruneConfig(Set.of(), keepArtifacts, ELIGIBLE_SCOPES, exclusions);
  }

  private static Set<ArtifactCoordinate> parsePassThroughCoordinates(
      final List<String> requested, final List<ArtifactSnapshot> snapshots)
      throws MojoFailureException {
    final Set<ArtifactCoordinate> result = new LinkedHashSet<>();
    if (requested == null) {
      return result;
    }
    for (final String raw : requested) {
      if (raw == null || raw.isBlank()) {
        throw new MojoFailureException(
            "elide.trimSkipArtifacts must not contain blank coordinates");
      }
      final String[] parts = raw.trim().split(":", -1);
      if (parts.length < 3
          || parts.length > 5
          || parts[0].isBlank()
          || parts[1].isBlank()
          || parts[2].isBlank()) {
        throw new MojoFailureException(
            "Invalid elide.trimSkipArtifacts coordinate; expected "
                + "group:artifact:version[:type[:classifier]]: "
                + raw);
      }
      final String type = optionalPiece(parts, 3, "jar");
      final String classifier = optionalPiece(parts, 4, "");
      if (!"jar".equals(type)) {
        throw new MojoFailureException(
            "elide.trimSkipArtifacts supports JAR artifacts only: " + raw);
      }
      final List<ArtifactSnapshot> matches =
          snapshots.stream()
              .filter(
                  snapshot -> {
                    final ArtifactCoordinate coordinate = snapshot.coordinate();
                    return coordinate.groupId().equals(parts[0])
                        && coordinate.artifactId().equals(parts[1])
                        && coordinate.version().equals(parts[2])
                        && coordinate.type().equals(type)
                        && coordinate.classifier().equals(classifier)
                        && ELIGIBLE_SCOPES.contains(coordinate.scope())
                        && snapshot.filePath() != null;
                  })
              .toList();
      if (matches.isEmpty()) {
        throw new MojoFailureException(
            "elide.trimSkipArtifacts coordinate is not a resolved compile/runtime JAR: " + raw);
      }
      matches.stream().map(ArtifactSnapshot::coordinate).forEach(result::add);
    }
    return result;
  }

  private static ElisionDecision retainNonJarArtifacts(
      final ElisionDecision jarDecision, final List<ArtifactSnapshot> snapshots) {
    final Set<ArtifactCoordinate> retained = new HashSet<>(jarDecision.retainedArtifacts());
    for (final ArtifactSnapshot snapshot : snapshots) {
      if (!"jar".equals(snapshot.coordinate().type()) && snapshot.filePath() != null) {
        retained.add(snapshot.coordinate());
      }
    }
    return new ElisionDecision(
        retained,
        jarDecision.elidedArtifacts(),
        jarDecision.retainedClassesPerArtifact(),
        jarDecision.unusedClassesPerArtifact(),
        jarDecision.elapsedNanos());
  }

  static DynamicRootInputs dynamicRoots(final List<ArtifactFileRef> candidates) throws IOException {
    return dynamicRoots(candidates, DependencyDynamicRoots::scan, Set.of(), true);
  }

  static DynamicRootInputs dynamicRoots(
      final List<ArtifactFileRef> candidates, final DynamicRootScanner scanner) throws IOException {
    return dynamicRoots(candidates, scanner, Set.of(), true);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  static DynamicRootInputs dynamicRoots(
      final List<ArtifactFileRef> candidates,
      final DynamicRootScanner scanner,
      final Set<String> provenServiceInterfaces,
      final boolean conservativeServiceLoaderRoots)
      throws IOException {
    final Set<String> classNames = new HashSet<>();
    final Set<ArtifactCoordinate> declaringArtifacts = new HashSet<>();
    final Map<Path, DependencyDynamicRoots.RootScan> scansByPath = new LinkedHashMap<>();
    final Map<ArtifactCoordinate, Set<String>> unprovenRootsByCoordinate = new LinkedHashMap<>();
    for (final ArtifactFileRef candidate : candidates) {
      DependencyDynamicRoots.RootScan scan = scansByPath.get(candidate.filePath());
      if (scan == null) {
        scan = scanner.scan(candidate.filePath());
        scansByPath.put(candidate.filePath(), scan);
      }
      final DependencyDynamicRoots.EffectiveRoots effective =
          scan.effectiveRoots(provenServiceInterfaces, conservativeServiceLoaderRoots);
      classNames.addAll(effective.roots());
      if (effective.declaresRoots()) {
        declaringArtifacts.add(candidate.coordinate());
      }
      if (!effective.unprovenConservativeRoots().isEmpty()) {
        unprovenRootsByCoordinate.put(
            candidate.coordinate(), effective.unprovenConservativeRoots());
      }
    }
    return new DynamicRootInputs(
        classNames,
        declaringArtifacts,
        scansByPath,
        unprovenRootsByCoordinate,
        provenServiceInterfaces);
  }

  private static Set<String> requiredClassesForTrimming(
      final Set<String> sourceClasses,
      final Set<String> dynamicClasses,
      final List<String> explicitRoots,
      final ArtifactClassIndex index,
      final boolean trimJars)
      throws IOException {
    final Set<String> required = new HashSet<>(sourceClasses);
    required.addAll(dynamicClasses);
    if (!trimJars) {
      return required;
    }
    final Set<String> indexedNames = new HashSet<>();
    index.classesByArtifact().values().forEach(indexedNames::addAll);
    if (explicitRoots != null) {
      for (final String root : explicitRoots) {
        if (root == null || root.isBlank()) {
          throw new IOException("elide.trimRoots must not contain blank class names");
        }
        final String normalized = TraceData.normalizeToDot(root.trim());
        if (!indexedNames.contains(normalized)) {
          throw new IOException(
              "elide.trimRoots class is not present in a dependency JAR: " + root);
        }
        required.add(normalized);
      }
    }
    return Set.copyOf(required);
  }

  private static Set<ArtifactCoordinate> dynamicRootArtifactOwners(
      final DynamicRootInputs dynamicRoots,
      final ArtifactClassIndex index,
      final List<ArtifactFileRef> inventory) {
    final Map<String, Set<ArtifactCoordinate>> ownersByClass = new ConcurrentHashMap<>();
    index
        .classesByArtifact()
        .forEach(
            (artifact, classes) ->
                classes.forEach(
                    className ->
                        ownersByClass
                            .computeIfAbsent(
                                className.replace('/', '.'),
                                ignored -> ConcurrentHashMap.newKeySet())
                            .add(artifact.coordinate())));
    final Set<ArtifactCoordinate> result = new HashSet<>();
    boolean unresolvedOwner = false;
    for (final String rawRoot : dynamicRoots.classNames()) {
      final Set<ArtifactCoordinate> owners =
          ownersByClass.getOrDefault(rawRoot.replace('/', '.'), Set.of());
      if (owners.isEmpty()) {
        unresolvedOwner = true;
      } else {
        result.addAll(owners);
      }
    }
    if (unresolvedOwner) {
      inventory.stream().map(ArtifactFileRef::coordinate).forEach(result::add);
    }
    return Set.copyOf(result);
  }

  private static Set<String> classNamesInOutput(final Path output) throws IOException {
    final Set<String> names = new LinkedHashSet<>();
    try (java.util.stream.Stream<Path> paths = Files.walk(output)) {
      for (final Path path : paths.filter(Files::isRegularFile).toList()) {
        final String name = output.relativize(path).toString().replace('\\', '/');
        if (!name.endsWith(".class")
            || "module-info.class".equals(name)
            || name.endsWith("/module-info.class")) {
          continue;
        }
        names.add(TraceData.normalizeToDot(name.substring(0, name.length() - 6)));
      }
    }
    return Set.copyOf(names);
  }

  /** Resolves source roots or retains all compiler-visible classes. */
  private static CompilerInputs compilerInputs(
      final MavenProject project,
      final MavenSession session,
      final List<ArtifactFileRef> candidates,
      final ArtifactClassIndex index,
      final boolean sourceRootsComplete)
      throws IOException {
    final List<String> classpath;
    try {
      classpath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the Maven compile classpath for source analysis", exception);
    }
    final Set<Path> compileClasspath = normalizedPaths(classpath);
    final Set<ArtifactFileRef> compileVisibleArtifacts = new HashSet<>();
    for (final ArtifactFileRef candidate : candidates) {
      final String scope = candidate.coordinate().scope();
      if (COMPILE_VISIBLE_SCOPES.contains(scope)
          || compileClasspath.contains(candidate.filePath().toAbsolutePath().normalize())) {
        compileVisibleArtifacts.add(candidate);
      }
    }
    final Set<String> requiredClasses = new HashSet<>();
    final Map<ArtifactFileRef, Set<String>> indexedClasses = index.classesByArtifact();
    if (sourceRootsComplete) {
      final List<Path> sources =
          JavaSourceReferenceScanner.sourceFiles(project.getCompileSourceRoots());
      verifySourceRootsComplete(project, sources);
      if (sources.stream().anyMatch(MavenElisionService::isModuleDescriptor)) {
        throw new IOException("Source attribution does not support Java module descriptors");
      }
      final List<String> options = MavenCompilerSettings.options(project, session, classpath);
      final JavaSourceReferenceScanner.SourceScan sourceScan =
          new JavaSourceReferenceScanner().scanFilesDetailed(sources, classpath, options);
      requiredClasses.addAll(sourceScan.referencedTypes());
      compileVisibleArtifacts.removeIf(
          artifact -> !sourceClassesByArtifact(artifact, requiredClasses, indexedClasses));
      return new CompilerInputs(
          compileVisibleArtifacts.stream()
              .map(ArtifactFileRef::coordinate)
              .collect(java.util.stream.Collectors.toSet()),
          requiredClasses,
          sourceScan.declaredTypes());
    } else {
      compileVisibleArtifacts.forEach(
          artifact -> requiredClasses.addAll(indexedClasses.getOrDefault(artifact, Set.of())));
    }
    final Set<ArtifactCoordinate> compileVisibleCoordinates = new HashSet<>();
    compileVisibleArtifacts.forEach(
        artifact -> compileVisibleCoordinates.add(artifact.coordinate()));
    return new CompilerInputs(compileVisibleCoordinates, requiredClasses, Set.of());
  }

  private static boolean sourceClassesByArtifact(
      final ArtifactFileRef artifact,
      final Set<String> requiredClasses,
      final Map<ArtifactFileRef, Set<String>> indexedClasses) {
    return indexedClasses.getOrDefault(artifact, Set.of()).stream()
        .anyMatch(requiredClasses::contains);
  }

  private static boolean isModuleDescriptor(final Path source) {
    final Path fileName = source.getFileName();
    return fileName != null && "module-info.java".equals(fileName.toString());
  }

  private static void verifySourceRootsComplete(
      final MavenProject project, final List<Path> currentSources) throws IOException {
    if (currentSources.isEmpty()) {
      throw new IOException(
          "elide.sourceRootsComplete=true requires current production Java sources");
    }
    for (final String root : project.getCompileSourceRoots()) {
      if (!Files.isDirectory(Path.of(root))) {
        throw new IOException("A declared production source root is not present: " + root);
      }
    }
    if (hasUnknownSourceGeneration(project)) {
      throw new IOException(
          "elide.sourceRootsComplete=true conflicts with a source-generation lifecycle execution");
    }
  }

  static boolean hasUnknownSourceGeneration(final MavenProject project) {
    final org.apache.maven.model.Build build = project.getBuild();
    if (build == null
        || !Set.of("jar", "pom", "war", "maven-plugin").contains(project.getPackaging())
        || !build.getExtensions().isEmpty()) {
      return true;
    }
    for (final Plugin plugin : build.getPlugins()) {
      for (final PluginExecution execution : plugin.getExecutions()) {
        if (!isKnownNonGeneratingExecution(plugin, execution)
            && (execution.getPhase() == null
                || phaseCanAddProductionSources(execution.getPhase()))) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isKnownNonGeneratingExecution(
      final Plugin plugin, final PluginExecution execution) {
    if ("org.apache.maven.plugins".equals(plugin.getGroupId())
        && "maven-resources-plugin".equals(plugin.getArtifactId())) {
      return execution.getGoals().stream().allMatch("resources"::equals);
    }
    if ("org.apache.maven.plugins".equals(plugin.getGroupId())
        && "maven-compiler-plugin".equals(plugin.getArtifactId())) {
      return execution.getGoals().stream().allMatch(Set.of("compile", "testCompile")::contains);
    }
    if ("org.apache.maven.plugins".equals(plugin.getGroupId())
        && "maven-enforcer-plugin".equals(plugin.getArtifactId())) {
      return execution.getGoals().stream().allMatch("enforce"::equals);
    }
    return "io.github.spockz".equals(plugin.getGroupId())
        && "dependency-elider-maven-plugin".equals(plugin.getArtifactId())
        && execution.getGoals().stream().allMatch(Set.of("elide", "analyze")::contains);
  }

  private static boolean phaseCanAddProductionSources(final String phase) {
    return Set.of(
            "validate",
            "initialize",
            "generate-sources",
            "process-sources",
            "generate-resources",
            "process-resources",
            "compile")
        .contains(phase);
  }

  private static Set<Path> normalizedPaths(final List<String> classpath) throws IOException {
    final Set<Path> paths = new HashSet<>();
    for (final String entry : classpath) {
      try {
        paths.add(Path.of(entry).toAbsolutePath().normalize());
      } catch (final InvalidPathException exception) {
        throw new IOException("Invalid Maven compile classpath entry: " + entry, exception);
      }
    }
    return paths;
  }

  private record CompilerInputs(
      Set<ArtifactCoordinate> compileVisibleCoordinates,
      Set<String> requiredClasses,
      Set<String> declaredClasses) {
    private CompilerInputs {
      compileVisibleCoordinates = Set.copyOf(compileVisibleCoordinates);
      requiredClasses = Set.copyOf(requiredClasses);
      declaredClasses = Set.copyOf(declaredClasses);
    }
  }

  private record ProductionBytecodeInputs(
      String fingerprint, Optional<BytecodeReferenceScan> scan) {}

  private static ProductionBytecodeInputs productionBytecodeInputs(final File output)
      throws IOException {
    if (output == null) {
      return new ProductionBytecodeInputs("none", Optional.empty());
    }
    final Path path = output.toPath();
    final String before = ProductionOutputFingerprint.fingerprint(path);
    final BytecodeReferenceScan scan = new ProductionBytecodeReferenceScanner().scan(path);
    final String after = ProductionOutputFingerprint.fingerprint(path);
    if (!before.equals(after)) {
      throw new IOException("Production output changed during bytecode analysis");
    }
    return new ProductionBytecodeInputs(before, Optional.of(scan));
  }

  /** Scans one dependency archive during an analysis invocation. */
  @FunctionalInterface
  interface DynamicRootScanner {
    /** Returns the dynamic roots declared by the archive. */
    DependencyDynamicRoots.RootScan scan(Path path) throws IOException;
  }

  /** Holds invocation roots and the scans reused by retained-JAR trimming. */
  record DynamicRootInputs(
      Set<String> classNames,
      Set<ArtifactCoordinate> declaringArtifacts,
      Map<Path, DependencyDynamicRoots.RootScan> scansByPath,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRootsByCoordinate,
      Set<String> provenServiceInterfaces) {
    DynamicRootInputs {
      classNames = Set.copyOf(classNames);
      declaringArtifacts = Set.copyOf(declaringArtifacts);
      scansByPath = Map.copyOf(scansByPath);
      unprovenServiceRootsByCoordinate = Map.copyOf(unprovenServiceRootsByCoordinate);
      provenServiceInterfaces = Set.copyOf(provenServiceInterfaces);
    }

    DynamicRootInputs(
        final Set<String> classNames,
        final Set<ArtifactCoordinate> declaringArtifacts,
        final Map<Path, DependencyDynamicRoots.RootScan> scansByPath) {
      this(classNames, declaringArtifacts, scansByPath, Map.of(), Set.of());
    }
  }

  private static ArtifactCoordinate parseExclusion(final String text) throws MojoFailureException {
    final String[] pieces = text.split(":", -1);
    if (pieces.length < 2 || pieces.length > 5 || pieces[0].isBlank() || pieces[1].isBlank()) {
      throw new MojoFailureException(
          "Invalid elide.excludedArtifacts coordinate '"
              + text
              + "'; expected groupId:artifactId[:version[:type[:classifier]]]");
    }
    final String version = optionalPiece(pieces, 2, null);
    final String type = optionalPiece(pieces, 3, "jar");
    final String classifier = optionalPiece(pieces, 4, "");
    return new ArtifactCoordinate(pieces[0], pieces[1], version, type, classifier, "compile");
  }

  private static String optionalPiece(
      final String[] pieces, final int index, final String defaultValue) {
    return pieces.length > index && !pieces[index].isBlank() ? pieces[index] : defaultValue;
  }

  private static Collection<Path> toPaths(final List<File> files) {
    return files == null ? List.of() : files.stream().map(File::toPath).toList();
  }

  private static Set<ArtifactIdentity> identities(
      final Collection<ArtifactCoordinate> coordinates) {
    final Set<ArtifactIdentity> result = new LinkedHashSet<>();
    for (final ArtifactCoordinate coordinate : coordinates) {
      result.add(ArtifactIdentity.from(coordinate));
    }
    return result;
  }

  private static Set<Artifact> retained(
      final Collection<Artifact> input, final Set<ArtifactIdentity> elided) {
    final Set<Artifact> result = new LinkedHashSet<>();
    for (final Artifact artifact : input) {
      if (!elided.contains(ArtifactIdentity.from(toCoordinate(artifact)))) {
        result.add(artifact);
      }
    }
    return result;
  }

  @SuppressWarnings({"PMD.CyclomaticComplexity", "PMD.UseConcurrentHashMap"})
  private static void validateIdentityPaths(final List<ArtifactSnapshot> snapshots)
      throws IOException {
    final Map<ArtifactIdentity, Path> paths = new LinkedHashMap<>();
    for (final ArtifactSnapshot snapshot : snapshots) {
      if (!"jar".equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path file = snapshot.filePath();
      if (file == null) {
        throw new IOException(
            "Resolved artifact has no regular JAR file: " + snapshot.coordinate());
      }
      final Path fileName = file.getFileName();
      if (fileName == null || !Files.isRegularFile(file) || !fileName.toString().endsWith(".jar")) {
        throw new IOException(
            "Resolved artifact has no regular JAR file: " + snapshot.coordinate());
      }
      final ArtifactIdentity identity = ArtifactIdentity.from(snapshot.coordinate());
      final Path previous = paths.putIfAbsent(identity, file);
      if (previous != null && !previous.equals(file)) {
        throw new IOException("Conflicting files for artifact identity " + identity);
      }
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static void validateDirectPaths(
      final Collection<ArtifactSnapshot> resolved, final Collection<ArtifactSnapshot> direct)
      throws IOException {
    final Map<ArtifactIdentity, Path> resolvedPaths = new LinkedHashMap<>();
    for (final ArtifactSnapshot snapshot : resolved) {
      if ("jar".equals(snapshot.coordinate().type()) && snapshot.filePath() != null) {
        resolvedPaths.put(ArtifactIdentity.from(snapshot.coordinate()), snapshot.filePath());
      }
    }
    for (final ArtifactSnapshot snapshot : direct) {
      final ArtifactIdentity identity = ArtifactIdentity.from(snapshot.coordinate());
      final Path resolvedPath = resolvedPaths.get(identity);
      final Path file = snapshot.filePath();
      if (resolvedPath != null && file != null && !resolvedPath.equals(file)) {
        throw new IOException("Conflicting direct artifact file for identity " + identity);
      }
    }
  }

  record PreparedAnalysis(
      MavenProject project,
      AnalysisOptions options,
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots,
      ElisionDecision rawDecision,
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan,
      List<ArtifactFileRef> scanCandidates,
      TraceData trace,
      ArtifactClassIndex index,
      DynamicRootInputs dynamicRootInputs,
      Set<String> projectOutputClasses,
      Set<String> sourceRequiredClasses,
      Set<String> pruningRequiredClasses,
      String productionOutputFingerprint,
      String inputFingerprint,
      String directInputFingerprint,
      MavenElisionGraphBinding.Result graphBinding) {
    PreparedAnalysis {
      resolvedSnapshots = List.copyOf(resolvedSnapshots);
      directSnapshots = List.copyOf(directSnapshots);
      scanCandidates = List.copyOf(scanCandidates);
      projectOutputClasses = Set.copyOf(projectOutputClasses);
      sourceRequiredClasses = Set.copyOf(sourceRequiredClasses);
      pruningRequiredClasses = Set.copyOf(pruningRequiredClasses);
      java.util.Objects.requireNonNull(productionOutputFingerprint, "productionOutputFingerprint");
    }
  }

  record EffectiveAnalysis(
      PreparedAnalysis prepared,
      EffectiveGraphPolicy.Evaluation graphEvaluation,
      ElisionDecision rawDecision,
      ElisionDecision effectiveDecision,
      Set<ArtifactCoordinate> forcedUnchangedCoordinates,
      MavenDependencyTrimmer.InMemoryAnalysis trimAnalysis,
      String inventoryFingerprint,
      String operationFingerprint,
      ResolverArtifactGraphProjection graphProjection) {
    EffectiveAnalysis {
      forcedUnchangedCoordinates = Set.copyOf(forcedUnchangedCoordinates);
    }
  }

  record Analysis(
      List<ArtifactSnapshot> resolvedSnapshots,
      boolean directArtifactsPresent,
      List<ArtifactSnapshot> directSnapshots,
      ElisionDecision decision,
      ElisionDecision effectiveDecision,
      ClassUsageReport classUsageReport,
      Optional<BytecodeReferenceScan> bytecodeScan,
      List<ArtifactTrimRecord> trimRecords,
      List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      List<ArtifactCoordinate> configuredPassThroughArtifacts,
      int trimCacheHits,
      long maximumTrimCacheHitNanos,
      int trimAnalysisRuns,
      ResolverArtifactGraphProjection graphProjection,
      TrimOutputGenerationCommitHandle generationCommit,
      MediatedGraphReport mediatedGraph,
      Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots) {
    @SuppressWarnings("PMD.ExcessiveParameterList")
    // Keeps the legacy adapter while the result fields stay named.
    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision,
        final ElisionDecision effectiveDecision,
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan,
        final List<ArtifactTrimRecord> trimRecords,
        final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
        final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
        final List<ArtifactCoordinate> configuredPassThroughArtifacts,
        final int trimCacheHits,
        final long maximumTrimCacheHitNanos,
        final int trimAnalysisRuns,
        final ResolverArtifactGraphProjection graphProjection,
        final TrimOutputGenerationCommitHandle generationCommit,
        final MediatedGraphReport mediatedGraph) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          effectiveDecision,
          classUsageReport,
          bytecodeScan,
          trimRecords,
          multiReleasePassthroughArtifacts,
          moduleInfoPassthroughArtifacts,
          configuredPassThroughArtifacts,
          trimCacheHits,
          maximumTrimCacheHitNanos,
          trimAnalysisRuns,
          graphProjection,
          generationCommit,
          mediatedGraph,
          Map.of());
    }

    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision,
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan,
        final List<ArtifactTrimRecord> trimRecords,
        final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
        final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
        final List<ArtifactCoordinate> configuredPassThroughArtifacts,
        final int trimCacheHits,
        final long maximumTrimCacheHitNanos,
        final int trimAnalysisRuns,
        final Map<ArtifactCoordinate, Set<String>> unprovenServiceRoots) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          decision,
          classUsageReport,
          bytecodeScan,
          trimRecords,
          multiReleasePassthroughArtifacts,
          moduleInfoPassthroughArtifacts,
          configuredPassThroughArtifacts,
          trimCacheHits,
          maximumTrimCacheHitNanos,
          trimAnalysisRuns,
          null,
          null,
          null,
          unprovenServiceRoots);
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    // Keeps the legacy adapter while the result fields stay named.
    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision,
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan,
        final List<ArtifactTrimRecord> trimRecords,
        final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
        final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
        final List<ArtifactCoordinate> configuredPassThroughArtifacts,
        final int trimCacheHits,
        final long maximumCacheHitNanos,
        final int trimAnalysisRuns) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          decision,
          classUsageReport,
          bytecodeScan,
          trimRecords,
          multiReleasePassthroughArtifacts,
          moduleInfoPassthroughArtifacts,
          configuredPassThroughArtifacts,
          trimCacheHits,
          maximumCacheHitNanos,
          trimAnalysisRuns,
          null,
          null,
          null);
    }

    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision,
        final ClassUsageReport classUsageReport,
        final Optional<BytecodeReferenceScan> bytecodeScan) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          decision,
          classUsageReport,
          bytecodeScan,
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          0,
          0L,
          0,
          null,
          null,
          null);
    }

    Analysis(
        final List<ArtifactSnapshot> resolvedSnapshots,
        final boolean directArtifactsPresent,
        final List<ArtifactSnapshot> directSnapshots,
        final ElisionDecision decision) {
      this(
          resolvedSnapshots,
          directArtifactsPresent,
          directSnapshots,
          decision,
          decision,
          new ClassUsageReport(List.of()),
          Optional.empty(),
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          0,
          0L,
          0,
          null,
          null,
          null);
    }

    Analysis {
      resolvedSnapshots = List.copyOf(resolvedSnapshots);
      directSnapshots = List.copyOf(directSnapshots);
      trimRecords = List.copyOf(trimRecords);
      multiReleasePassthroughArtifacts = List.copyOf(multiReleasePassthroughArtifacts);
      moduleInfoPassthroughArtifacts = List.copyOf(moduleInfoPassthroughArtifacts);
      configuredPassThroughArtifacts = List.copyOf(configuredPassThroughArtifacts);
      unprovenServiceRoots =
          unprovenServiceRoots != null ? Map.copyOf(unprovenServiceRoots) : Map.of();
    }

    Set<Artifact> resolvedArtifacts() {
      return references(resolvedSnapshots);
    }

    Set<Artifact> directArtifacts() {
      return references(directSnapshots);
    }

    private static Set<Artifact> references(final List<ArtifactSnapshot> snapshots) {
      final Set<Artifact> result = new LinkedHashSet<>();
      snapshots.stream().map(ArtifactSnapshot::artifact).forEach(result::add);
      return Collections.unmodifiableSet(result);
    }
  }

  record ArtifactSnapshot(Artifact artifact, ArtifactCoordinate coordinate, Path filePath) {
    private static ArtifactSnapshot from(final Artifact artifact) {
      return new ArtifactSnapshot(artifact, toCoordinate(artifact), normalizedPath(artifact));
    }
  }

  record ApplyPlan(
      Set<Artifact> resolvedArtifacts,
      boolean directArtifactsPresent,
      Set<Artifact> directArtifacts) {
    ApplyPlan {
      resolvedArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(resolvedArtifacts));
      directArtifacts = Collections.unmodifiableSet(new LinkedHashSet<>(directArtifacts));
    }
  }

  record CurrentViews(List<Artifact> resolvedArtifacts, List<Artifact> directArtifacts) {
    CurrentViews {
      resolvedArtifacts = List.copyOf(resolvedArtifacts);
      directArtifacts = List.copyOf(directArtifacts);
    }
  }

  private record ArtifactIdentity(
      String groupId, String artifactId, String version, String type, String classifier) {
    private static ArtifactIdentity from(final ArtifactCoordinate coordinate) {
      return new ArtifactIdentity(
          coordinate.groupId(),
          coordinate.artifactId(),
          coordinate.version(),
          coordinate.type(),
          coordinate.classifier());
    }
  }
}
