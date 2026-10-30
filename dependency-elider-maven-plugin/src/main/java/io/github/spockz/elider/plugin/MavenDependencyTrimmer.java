/* WHY: Joins Maven's trace, compiler, bytecode, and dynamic metadata evidence to the per-JAR
 * ProGuard engine while keeping all artifact pointer changes outside the analysis transaction. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import proguard.classfile.ClassPool;

/** Creates sanitized outputs for retained dependency JARs without mutating Maven artifacts. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.CommentSize",
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CommentDefaultAccessModifier",
  "PMD.NcssCount",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.UseExplicitTypes",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap",
  "PMD.CompareObjectsWithEquals",
  "PMD.InsufficientStringBufferDeclaration",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.CommentRequired",
  "PMD.DataClass",
  "PMD.AvoidFieldNameMatchingMethodName"
})
final class MavenDependencyTrimmer {
  private static final String DO_NOT_USE_THREADS_SUPPRESSION = "PMD.DoNotUseThreads";
  private static final String DEFAULT_BUILD_DIRECTORY = "target";
  private static final String JAVA_HOME_PROPERTY = "java.home";
  private static final String CLASS_SUFFIX = ".class";
  static final String MRJAR_VERTICAL_SHADING = "vertical-shading";
  static final String MRJAR_PASS_THROUGH = "pass-through";
  private static final String ELIDED_ARTIFACTS = "elided-artifacts";
  static final String JAR_TYPE = "jar";
  private static final Set<String> TRIMMABLE_SCOPES = Set.of("compile", "runtime");
  static final Set<String> ANALYSIS_LIBRARY_SCOPES =
      Set.of("compile", "runtime", "provided", "system");
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  /** Cache schema used in the entry fingerprint and manifest envelope. */
  static final int CACHE_SCHEMA_VERSION = 1;

  /** Domain marker distinguishes this cache from incompatible pre-release drafts. */
  static final String CACHE_FORMAT_ID = "maven-dependency-elider-effective-output-cache";

  private static final String ENGINE_VERSION = "proguard-core-9.4.0";
  static final int DEFAULT_TRIM_WORKERS = 4;
  static final int MIN_TRIM_WORKERS = 1;
  private static final long CANCELLATION_GRACE_SECONDS = 30;

  record TrimResult(
      List<ArtifactTrimRecord> records,
      List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      List<ArtifactCoordinate> configuredPassThroughArtifacts,
      int cacheHits,
      long maximumCacheHitNanos,
      int analysisRuns,
      TrimOutputGenerationCommitHandle generationCommit) {
    TrimResult(
        final List<ArtifactTrimRecord> records,
        final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
        final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
        final List<ArtifactCoordinate> configuredPassThroughArtifacts,
        final int cacheHits,
        final long maximumCacheHitNanos,
        final int analysisRuns) {
      this(
          records,
          multiReleasePassthroughArtifacts,
          moduleInfoPassthroughArtifacts,
          configuredPassThroughArtifacts,
          cacheHits,
          maximumCacheHitNanos,
          analysisRuns,
          null);
    }

    TrimResult {
      records =
          records.stream().sorted(Comparator.comparing(ArtifactTrimRecord::coordinate)).toList();
      multiReleasePassthroughArtifacts =
          multiReleasePassthroughArtifacts.stream().sorted().toList();
      moduleInfoPassthroughArtifacts = moduleInfoPassthroughArtifacts.stream().sorted().toList();
      configuredPassThroughArtifacts = configuredPassThroughArtifacts.stream().sorted().toList();
    }
  }

  record ScanInputs(
      ArtifactClassIndex classIndex, Map<Path, DependencyDynamicRoots.RootScan> dynamicRootScans) {}

  private record CacheManifest(
      int schemaVersion, String formatId, String fingerprint, List<CacheEntry> entries) {}

  private record FingerprintSnapshot(
      String value,
      Map<Path, ArtifactDigests> inputDigests,
      List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {}

  private record FingerprintOptions(
      int runtimeRelease,
      int release,
      int schemaVersion,
      String engineVersion,
      JdkPlatformContext platformContext,
      List<Integer> analyzedTiers,
      String outputContext) {}

  private record CacheOutputMetadata(
      String originalSha1,
      String trimmedPath,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      long prunedClassBytes,
      Integer originalPhysicalEntries,
      Integer trimmedPhysicalEntries,
      String mrjarStatus) {}

  private record TieringDecision(boolean required, boolean hasVerticalShadingCandidate) {}

  private record PlatformPools(ClassPool compiler, ClassPool runtime) {}

  private record IndexedResult<R>(int index, R value) {}

  private record CandidatePlan(
      List<Path> retainedInputPaths,
      List<CandidateWork> work,
      Map<String, List<CandidateWork>> ownersByClass,
      Map<String, Path> ownerByClass) {}

  private record CommonRootOwners(
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> byArtifact,
      Set<ArtifactCoordinate> droppedArtifacts) {}

  private record SingleReleaseInventory(
      List<MavenElisionService.ArtifactSnapshot> artifacts,
      List<MavenElisionService.ArtifactSnapshot> retainedLibraries,
      Map<MavenElisionService.ArtifactSnapshot, Path> analysisPaths,
      Map<Path, Set<String>> classesByPath,
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> classesByArtifact,
      Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass,
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> requestedRoots) {}

  private record SingleReleaseLayout(
      Set<ArtifactCoordinate> retainedCoordinates,
      List<MavenElisionService.ArtifactSnapshot> eligible,
      List<MavenElisionService.ArtifactSnapshot> candidates,
      List<MavenElisionService.ArtifactSnapshot> unchangedPrograms,
      Set<ArtifactCoordinate> skippedProgramCoordinates,
      Set<String> unchangedPassThroughClasses) {}

  private record DynamicRootPlan(
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> rootsByOwner,
      Set<ArtifactCoordinate> droppedArtifacts) {}

  private record SingleReleaseRootPlan(
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
      Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          preparedCandidates,
      Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          preparedPrograms,
      Set<ArtifactCoordinate> reachableArtifacts) {}

  private record SingleReleaseClosure(
      Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses,
      Set<ArtifactCoordinate> reachableArtifacts,
      int analysisRuns) {}

  record PassThroughPlan(
      List<MavenElisionService.ArtifactSnapshot> retainedLibraries,
      List<MavenElisionService.ArtifactSnapshot> retained,
      Set<String> multiReleaseIdentities,
      Set<String> moduleInfoIdentities,
      Set<String> skippedArtifactIdentities,
      List<ArtifactCoordinate> multiReleaseCoordinates,
      List<ArtifactCoordinate> moduleInfoCoordinates,
      List<ArtifactCoordinate> configuredCoordinates) {}

  private record EffectiveOutputPlan(
      MavenElisionService.PreparedAnalysis prepared,
      MavenDependencyTrimmer.InMemoryAnalysis analysis,
      Map<ArtifactRootKey, Set<String>> roots,
      Set<ArtifactCoordinate> unchangedCoordinates,
      Set<ArtifactCoordinate> retainedCoordinates,
      String inventoryFingerprint,
      String directInventoryFingerprint,
      String operationFingerprint,
      String productionOutputFingerprint,
      Set<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      String mrjarStrategy,
      boolean failOnUnsupportedModuleInfo,
      TrimOutputGenerationPublisher.MoveOperation move) {
    private EffectiveOutputPlan {
      roots = immutableRootMap(roots);
      unchangedCoordinates = Set.copyOf(unchangedCoordinates);
      retainedCoordinates = Set.copyOf(retainedCoordinates);
      bytecodeReferences = Set.copyOf(bytecodeReferences);
      explicitRoots = List.copyOf(explicitRoots);
      explicitPassThroughCoordinates = List.copyOf(explicitPassThroughCoordinates);
    }
  }

  private record EffectivePublication(
      EffectiveOutputPlan outputPlan,
      List<CandidateWork> work,
      FingerprintSnapshot fingerprint,
      Path manifest,
      String completeFingerprint,
      List<ArtifactCoordinate> multiRelease,
      List<ArtifactCoordinate> moduleInfo,
      List<ArtifactCoordinate> configured,
      int analysisRuns) {
    private EffectivePublication {
      work = List.copyOf(work);
      multiRelease = List.copyOf(multiRelease);
      moduleInfo = List.copyOf(moduleInfo);
      configured = List.copyOf(configured);
    }
  }

  private record PreparedEffectiveOutputs(
      Map<CandidateWork, CacheEntry> entries, List<ArtifactTrimRecord> records) {}

  private static final class EffectiveOutputStaging implements AutoCloseable {
    private final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    private final PreparedOutputCleanup preparedOutputCleanup =
        new PreparedOutputCleanup(sanitizer);
    private final Path stagedGeneration;

    private EffectiveOutputStaging(final Path stagedGeneration, final Path stagedManifest) {
      this.stagedGeneration = stagedGeneration;
      preparedOutputCleanup.addCleanupAction(() -> Files.deleteIfExists(stagedManifest));
      preparedOutputCleanup.addCleanupAction(() -> deleteTree(stagedGeneration));
    }

    private PreparedEffectiveOutputs prepareOutputs(
        final List<CandidateWork> work,
        final Map<Path, ArtifactDigests> inputDigests,
        final EffectiveOutputPlan outputPlan,
        final int trimWorkers)
        throws IOException {
      final Map<CandidateWork, CacheEntry> entries = new java.util.HashMap<>();
      final List<ArtifactTrimRecord> records = new ArrayList<>();
      final List<CandidateWork> toSanitize = new ArrayList<>();
      for (final CandidateWork candidate : work) {
        final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
        if (analysis == null) {
          continue;
        }
        if (!candidate.requiresOutput()) {
          entries.put(candidate, cacheEntry(candidate, null, inputDigests));
          continue;
        }
        toSanitize.add(candidate);
      }
      final ServiceProviderInventory providerInventory =
          toSanitize.stream().anyMatch(CandidateWork::isMultiRelease)
              ? serviceProviderInventory(outputPlan, work)
              : new ServiceProviderInventory(Set.of(), Set.of());
      final List<PendingOutput> prepared =
          mapParallel(
              toSanitize,
              trimWorkers,
              candidate -> {
                final Path stagedOutput =
                    stagedGeneration.resolve(candidate.output().getFileName());
                final ArchiveSanitizer.PreparedOutput staged;
                if (candidate.isMultiRelease()) {
                  final Set<String> removedProviders =
                      removedServiceProviders(
                          candidate,
                          new ScanInputs(
                              outputPlan.prepared().index(),
                              outputPlan.prepared().dynamicRootInputs().scansByPath()),
                          providerInventory);
                  final MultiReleaseArchivePlan plan =
                      MultiReleaseArchivePlan.create(
                          candidate.snapshot().filePath(),
                          outputPlan.analysis().compilerRelease(),
                          candidate.analysis().retainedClasses(),
                          removedProviders);
                  staged =
                      sanitizer.prepareMultiRelease(
                          candidate.snapshot().filePath(),
                          stagedOutput,
                          candidate.snapshot().coordinate(),
                          candidate.analysis(),
                          plan,
                          requiredInputDigest(inputDigests, candidate.snapshot().filePath())
                              .sha256());
                } else {
                  staged =
                      sanitizer.prepareWithProvenance(
                          candidate.snapshot().filePath(),
                          stagedOutput,
                          candidate.snapshot().coordinate(),
                          candidate.analysis(),
                          requiredInputDigest(inputDigests, candidate.snapshot().filePath()));
                }
                return preparedOutputCleanup.track(new PendingOutput(candidate, staged));
              },
              preparedOutputCleanup);
      final List<ArtifactTrimRecord> stagedRecords =
          publishOutputs(
              prepared.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
      for (int index = 0; index < prepared.size(); index++) {
        final PendingOutput pending = prepared.get(index);
        final ArtifactTrimRecord staged = stagedRecords.get(index);
        final ArtifactTrimRecord record =
            new ArtifactTrimRecord(
                staged.coordinate(),
                staged.originalPath(),
                staged.originalSha256(),
                staged.originalSha1(),
                pending.candidate().output(),
                staged.trimmedSha256(),
                staged.trimmedSha1(),
                staged.totalClasses(),
                staged.retainedClasses(),
                staged.prunedClassBytes(),
                staged.originalPhysicalEntries().orElseThrow(),
                staged.trimmedPhysicalEntries().orElseThrow(),
                staged.mrjarStatus());
        records.add(record);
        entries.put(pending.candidate(), cacheEntry(pending.candidate(), record, inputDigests));
      }
      return new PreparedEffectiveOutputs(Map.copyOf(entries), List.copyOf(records));
    }

    @Override
    public void close() throws IOException {
      preparedOutputCleanup.close();
    }
  }

  private record EffectiveCacheIdentity(
      int schema,
      String inventoryFingerprint,
      String directInventoryFingerprint,
      String operationFingerprint,
      String productionOutputFingerprint,
      List<ArtifactCacheIdentity> inventory,
      List<ArtifactCoordinate> retainedCoordinates,
      List<ArtifactCoordinate> unchangedCoordinates,
      List<ArtifactRootsIdentity> artifactRoots,
      int compilerRelease,
      int runtimeRelease,
      String javaHome,
      List<String> platformIdentities,
      List<Integer> analyzedTiers,
      List<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean productionClassesComplete,
      String mrjarStrategy,
      boolean failOnUnsupportedModuleInfo) {}

  private record ArtifactCacheIdentity(
      String groupId,
      String artifactId,
      String version,
      String type,
      String classifier,
      String scope,
      String path,
      String sha256) {}

  private record ArtifactRootsIdentity(
      ArtifactCoordinate coordinate, String path, String sha256, List<String> roots) {}

  private static Map<ArtifactRootKey, Set<String>> immutableRootMap(
      final Map<ArtifactRootKey, Set<String>> roots) {
    final Map<ArtifactRootKey, Set<String>> result = new java.util.LinkedHashMap<>();
    roots.entrySet().stream()
        .sorted(
            Comparator.comparing(
                    (Map.Entry<ArtifactRootKey, Set<String>> entry) -> entry.getKey().coordinate())
                .thenComparing(entry -> entry.getKey().path()))
        .forEach(
            entry ->
                result.put(
                    entry.getKey(),
                    java.util.Collections.unmodifiableSet(new TreeSet<>(entry.getValue()))));
    return java.util.Collections.unmodifiableMap(result);
  }

  private static Map<ArtifactRootKey, Set<String>> artifactRootKeys(
      final List<MavenElisionService.ArtifactSnapshot> inventory,
      final Map<ArtifactCoordinate, Set<String>> rootsByCoordinate)
      throws IOException {
    final Map<ArtifactRootKey, Set<String>> result = new java.util.LinkedHashMap<>();
    for (final Map.Entry<ArtifactCoordinate, Set<String>> entry : rootsByCoordinate.entrySet()) {
      final MavenElisionService.ArtifactSnapshot owner =
          inventory.stream()
              .filter(snapshot -> snapshot.coordinate().equals(entry.getKey()))
              .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
              .findFirst()
              .orElseThrow(
                  () ->
                      new IOException(
                          "Effective roots have no inventory artifact: " + entry.getKey()));
      final Path path = owner.filePath().toAbsolutePath().normalize();
      result.put(
          new ArtifactRootKey(entry.getKey(), path, ArtifactDigests.read(path).sha256()),
          entry.getValue());
    }
    return java.util.Collections.unmodifiableMap(result);
  }

  private record AnalysisLibraries(
      List<Path> paths, List<SkippedProgram> skippedPrograms, Set<String> passThroughClassNames) {}

  private record CacheEntry(
      String originalPath,
      String originalSha256,
      String originalSha1,
      String trimmedPath,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      Long prunedClassBytes,
      Set<String> roots,
      Set<String> retainedClassNames,
      Set<String> reachableLibraryClasses,
      Integer originalPhysicalEntries,
      Integer trimmedPhysicalEntries,
      String mrjarStatus) {}

  @SuppressWarnings("PMD.ExcessiveParameterList")
  record TrimRequest(
      MavenProject project,
      MavenSession session,
      List<MavenElisionService.ArtifactSnapshot> candidates,
      ScanInputs scanInputs,
      Set<ArtifactCoordinate> retainedCoordinates,
      TraceData trace,
      Set<String> sourceRoots,
      Set<String> bytecodeRoots,
      Set<String> projectOutputClasses,
      List<String> explicitRoots,
      boolean failOnUnsupportedMultiRelease,
      List<String> explicitPassThroughCoordinates,
      boolean failOnUnsupportedModuleInfo,
      String mrjarStrategy,
      boolean trimEnabled,
      Set<String> provenServiceInterfaces,
      boolean conservativeServiceLoaderRoots,
      int trimWorkers) {
    TrimRequest {
      if (trimWorkers < MIN_TRIM_WORKERS) {
        throw new IllegalArgumentException("trimWorkers must be at least 1");
      }
    }

    TrimRequest(
        final MavenProject project,
        final MavenSession session,
        final List<MavenElisionService.ArtifactSnapshot> candidates,
        final ScanInputs scanInputs,
        final Set<ArtifactCoordinate> retainedCoordinates,
        final TraceData trace,
        final Set<String> sourceRoots,
        final Set<String> bytecodeRoots,
        final Set<String> projectOutputClasses,
        final List<String> explicitRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> explicitPassThroughCoordinates,
        final boolean failOnUnsupportedModuleInfo,
        final Set<String> provenServiceInterfaces,
        final boolean conservativeServiceLoaderRoots) {
      this(
          project,
          session,
          candidates,
          scanInputs,
          retainedCoordinates,
          trace,
          sourceRoots,
          bytecodeRoots,
          projectOutputClasses,
          explicitRoots,
          failOnUnsupportedMultiRelease,
          explicitPassThroughCoordinates,
          failOnUnsupportedModuleInfo,
          MRJAR_VERTICAL_SHADING,
          true,
          provenServiceInterfaces,
          conservativeServiceLoaderRoots,
          DEFAULT_TRIM_WORKERS);
    }

    TrimRequest(
        final MavenProject project,
        final MavenSession session,
        final List<MavenElisionService.ArtifactSnapshot> candidates,
        final ScanInputs scanInputs,
        final Set<ArtifactCoordinate> retainedCoordinates,
        final TraceData trace,
        final Set<String> sourceRoots,
        final Set<String> bytecodeRoots,
        final Set<String> projectOutputClasses,
        final List<String> explicitRoots,
        final boolean failOnUnsupportedMultiRelease,
        final List<String> explicitPassThroughCoordinates,
        final boolean failOnUnsupportedModuleInfo) {
      this(
          project,
          session,
          candidates,
          scanInputs,
          retainedCoordinates,
          trace,
          sourceRoots,
          bytecodeRoots,
          projectOutputClasses,
          explicitRoots,
          failOnUnsupportedMultiRelease,
          explicitPassThroughCoordinates,
          failOnUnsupportedModuleInfo,
          MRJAR_VERTICAL_SHADING,
          true,
          Set.of(),
          true,
          DEFAULT_TRIM_WORKERS);
    }
  }

  record ArtifactRootKey(ArtifactCoordinate coordinate, Path path, String sha256) {
    ArtifactRootKey {
      path = path.toAbsolutePath().normalize();
    }
  }

  record InMemoryAnalysis(
      Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> candidateAnalyses,
      Map<ArtifactCoordinate, Set<String>> candidateRoots,
      Set<ArtifactCoordinate> reachableArtifacts,
      int analysisRuns,
      int compilerRelease,
      int runtimeRelease,
      Path javaHome,
      List<String> platformIdentities,
      List<Integer> analyzedTiers,
      Map<ArtifactCoordinate, Set<String>> upperTierClasses) {
    InMemoryAnalysis {
      candidateAnalyses = immutableAnalysisMap(candidateAnalyses);
      candidateRoots = immutableSetMap(candidateRoots);
      reachableArtifacts = java.util.Collections.unmodifiableSet(new TreeSet<>(reachableArtifacts));
      javaHome = javaHome.toAbsolutePath().normalize();
      platformIdentities = List.copyOf(platformIdentities);
      analyzedTiers = analyzedTiers.stream().distinct().sorted().toList();
      upperTierClasses = immutableSetMap(upperTierClasses);
    }
  }

  private MavenDependencyTrimmer() {}

  static TrimResult trimEffectiveOutputs(final MavenElisionService.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return trimEffectiveOutputs(effective, TrimOutputGenerationPublisher::atomicMove);
  }

  static TrimResult trimEffectiveOutputs(
      final MavenElisionService.EffectiveAnalysis effective,
      final TrimOutputGenerationPublisher.MoveOperation move)
      throws IOException, MojoFailureException {
    final TrimResult result = stageEffectiveOutputs(effective, move);
    if (result.generationCommit() != null) {
      result.generationCommit().commit();
      result.generationCommit().cleanupCommitted();
    }
    return result;
  }

  static TrimResult stageEffectiveOutputs(final MavenElisionService.EffectiveAnalysis effective)
      throws IOException, MojoFailureException {
    return stageEffectiveOutputs(effective, TrimOutputGenerationPublisher::atomicMove);
  }

  static TrimResult stageEffectiveOutputs(
      final MavenElisionService.EffectiveAnalysis effective,
      final TrimOutputGenerationPublisher.MoveOperation move)
      throws IOException, MojoFailureException {
    final MavenElisionService.PreparedAnalysis prepared = effective.prepared();
    MavenElisionService.verifyPreparedInventory(prepared);
    final MavenElisionService.AnalysisOptions options = prepared.options();
    if (!options.trimJars()) {
      return new TrimResult(List.of(), List.of(), List.of(), List.of(), 0, 0L, 0);
    }
    final TrimRequest request =
        new TrimRequest(
            prepared.project(),
            options.session(),
            prepared.resolvedSnapshots(),
            new ScanInputs(prepared.index(), prepared.dynamicRootInputs().scansByPath()),
            effective.effectiveDecision().retainedArtifacts(),
            prepared.trace(),
            prepared.pruningRequiredClasses(),
            prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
            prepared.projectOutputClasses(),
            options.explicitTrimRoots(),
            options.failOnUnsupportedMultiRelease(),
            options.explicitPassThroughArtifacts(),
            options.failOnUnsupportedModuleInfo(),
            options.mrjarStrategy(),
            options.trimJars(),
            prepared.dynamicRootInputs().provenServiceInterfaces(),
            options.conservativeServiceLoaderRoots(),
            options.trimWorkers());
    final Map<ArtifactRootKey, Set<String>> roots =
        artifactRootKeys(prepared.resolvedSnapshots(), effective.trimAnalysis().candidateRoots());
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
            options.explicitTrimRoots(),
            options.explicitPassThroughArtifacts(),
            options.sourceRootsComplete(),
            options.productionClassesComplete(),
            options.mrjarStrategy(),
            options.failOnUnsupportedModuleInfo(),
            move);
    final MavenProject project = request.project();
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(project, request.session());
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int release = releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    verifyAnalysisPlatform(effective, release, runtimeRelease, javaHome);
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      return trimPrepared(request, release, runtimeRelease, context, outputPlan);
    }
  }

  static TrimResult trim(final TrimRequest request) throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final MavenSession session = request.session();
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(project, session);
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int release = releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    final JdkPlatformContext platformContext =
        MavenPlatformContextHolder.forOperation(session, javaHome);
    return trimPrepared(request, release, runtimeRelease, platformContext);
  }

  static InMemoryAnalysis analyzeInMemory(
      final TrimRequest request,
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    final TieringDecision decision = tieringDecision(request, forcedUnchanged);
    if (!decision.required()) {
      return analyzeInMemorySingleRelease(request, discoveredRoots, forcedUnchanged);
    }
    return analyzeInMemoryTiered(request, discoveredRoots, forcedUnchanged, decision);
  }

  private static TieringDecision tieringDecision(
      final TrimRequest request, final Set<ArtifactCoordinate> forcedUnchanged) throws IOException {
    if (!request.trimEnabled()) {
      return new TieringDecision(false, false);
    }
    final PassThroughPlan passThrough = passThroughPlan(request);
    final boolean otherTrimCandidate = hasOtherTrimCandidate(passThrough, forcedUnchanged);
    final boolean unchangedMrjarProgram =
        hasUnchangedMultiReleaseProgram(request, passThrough, forcedUnchanged);
    final boolean verticalCandidate =
        hasVerticalShadingCandidate(request, passThrough, forcedUnchanged);
    return new TieringDecision(
        verticalCandidate || (otherTrimCandidate && unchangedMrjarProgram), verticalCandidate);
  }

  private static boolean hasOtherTrimCandidate(
      final PassThroughPlan passThrough, final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    for (final MavenElisionService.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && !isMultiReleaseArchive(snapshot.filePath())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasUnchangedMultiReleaseProgram(
      final TrimRequest request,
      final PassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    for (final MavenElisionService.ArtifactSnapshot snapshot : passThrough.retainedLibraries()) {
      if (!isMultiReleaseArchive(snapshot.filePath())) {
        continue;
      }
      final boolean forced = forcedUnchanged.contains(snapshot.coordinate());
      final boolean skipped =
          passThrough.skippedArtifactIdentities().contains(artifactIdentity(snapshot.coordinate()));
      if (forced || skipped || MRJAR_PASS_THROUGH.equals(request.mrjarStrategy())) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasVerticalShadingCandidate(
      final TrimRequest request,
      final PassThroughPlan passThrough,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    if (!MRJAR_VERTICAL_SHADING.equals(request.mrjarStrategy())) {
      return false;
    }
    for (final MavenElisionService.ArtifactSnapshot snapshot : passThrough.retained()) {
      if (!forcedUnchanged.contains(snapshot.coordinate())
          && isMultiReleaseArchive(snapshot.filePath())) {
        return true;
      }
    }
    return false;
  }

  private static boolean isMultiReleaseArchive(final Path path) throws IOException {
    return MultiReleaseClassInventory.hasUnsupportedVersionedClasses(path);
  }

  private static InMemoryAnalysis analyzeInMemoryTiered(
      final TrimRequest request,
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final TieringDecision decision)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(project, request.session());
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int release = releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    if (release > runtimeRelease && decision.hasVerticalShadingCandidate()) {
      throw new IOException(
          "Compiler release " + release + " exceeds Maven runtime release " + runtimeRelease);
    }
    if (release > runtimeRelease) {
      return analyzeInMemorySingleRelease(request, discoveredRoots, forcedUnchanged);
    }
    return MultiReleaseTierAnalyzer.analyze(
        request, discoveredRoots, forcedUnchanged, release, runtimeRelease, javaHome);
  }

  private static InMemoryAnalysis analyzeInMemorySingleRelease(
      final TrimRequest request,
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException, MojoFailureException {
    final SingleReleaseInventory inventory = readSingleReleaseInventory(request, discoveredRoots);
    final SingleReleaseLayout layout = singleReleaseLayout(request, inventory, forcedUnchanged);
    final List<Path> fullClasspath = fullClasspath(inventory);
    final Path javaHome =
        Path.of(System.getProperty(JAVA_HOME_PROPERTY)).toAbsolutePath().normalize();
    final int runtimeRelease = Runtime.version().feature();
    final int release = analysisRelease(request, javaHome, runtimeRelease);
    final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots =
        platformSnapshots(javaHome, release, runtimeRelease);
    final PlatformPools pools = readPlatformPools(platformSnapshots, release, runtimeRelease);
    final TrimAnalysisSession analysisSession = new TrimAnalysisSession(new DependencyJarTrimmer());
    final SingleReleaseRootPlan roots =
        singleReleaseRootPlan(
            request,
            inventory,
            layout,
            fullClasspath,
            pools,
            analysisSession,
            request.trimWorkers());
    final SingleReleaseClosure closure =
        analyzeSingleReleaseClosure(inventory, layout, roots, request.trimWorkers());
    return inMemoryResult(
        closure.analyses(),
        roots.candidateRoots(),
        closure.reachableArtifacts(),
        closure.analysisRuns(),
        release,
        runtimeRelease,
        javaHome,
        platformSnapshots,
        Map.of());
  }

  private static SingleReleaseInventory readSingleReleaseInventory(
      final TrimRequest request, final Map<ArtifactRootKey, Set<String>> discoveredRoots)
      throws IOException {
    final List<MavenElisionService.ArtifactSnapshot> artifacts =
        request.candidates().stream()
            .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
            .toList();
    validateAnalysisInventory(artifacts);
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final List<MavenElisionService.ArtifactSnapshot> retainedLibraries =
        artifacts.stream()
            .filter(snapshot -> retainedCoordinates.contains(snapshot.coordinate()))
            .filter(snapshot -> ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope()))
            .toList();
    final Map<MavenElisionService.ArtifactSnapshot, Path> analysisPaths =
        analysisPaths(request, artifacts);
    final Map<Path, Set<String>> classesByPath = new java.util.LinkedHashMap<>();
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classesByArtifact =
        new java.util.LinkedHashMap<>();
    final Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass =
        new java.util.HashMap<>();
    populateSingleReleaseClassInventory(
        artifacts, analysisPaths, classesByPath, classesByArtifact, ownerByClass);
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> requestedRoots =
        validateDiscoveredRoots(discoveredRoots, artifacts, classesByPath);
    return new SingleReleaseInventory(
        artifacts,
        retainedLibraries,
        analysisPaths,
        classesByPath,
        classesByArtifact,
        ownerByClass,
        requestedRoots);
  }

  private static void populateSingleReleaseClassInventory(
      final List<MavenElisionService.ArtifactSnapshot> artifacts,
      final Map<MavenElisionService.ArtifactSnapshot, Path> analysisPaths,
      final Map<Path, Set<String>> classesByPath,
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classesByArtifact,
      final Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass)
      throws IOException {
    for (final MavenElisionService.ArtifactSnapshot snapshot : artifacts) {
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final Path analysisPath = analysisPaths.getOrDefault(snapshot, source);
      final Set<String> sourceClasses = classNames(source);
      final Set<String> classes =
          ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())
              ? classNames(analysisPath)
              : Set.of();
      classesByPath.put(source, sourceClasses);
      classesByArtifact.put(snapshot, classes);
      for (final String name : classes) {
        final MavenElisionService.ArtifactSnapshot previous =
            ownerByClass.putIfAbsent(name, snapshot);
        if (previous != null && !previous.equals(snapshot)) {
          throw new IOException("Duplicate class owner in complete JAR inventory: " + name);
        }
      }
    }
  }

  private static SingleReleaseLayout singleReleaseLayout(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final Set<ArtifactCoordinate> forcedUnchanged)
      throws IOException {
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final Set<ArtifactCoordinate> layoutPassThroughCoordinates = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      if (TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())
          && passThroughCoordinate(request, snapshot)) {
        layoutPassThroughCoordinates.add(snapshot.coordinate());
      }
    }
    final List<MavenElisionService.ArtifactSnapshot> eligible =
        inventory.retainedLibraries().stream()
            .filter(snapshot -> TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope()))
            .filter(snapshot -> !layoutPassThroughCoordinates.contains(snapshot.coordinate()))
            .toList();
    final List<MavenElisionService.ArtifactSnapshot> configuredPassThrough =
        parsePassThroughArtifacts(request.explicitPassThroughCoordinates(), eligible);
    final Set<String> passThroughIdentities = identities(configuredPassThrough);
    final Set<ArtifactCoordinate> skippedProgramCoordinates =
        new LinkedHashSet<>(layoutPassThroughCoordinates);
    skippedProgramCoordinates.addAll(forcedUnchanged);
    configuredPassThrough.stream()
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .forEach(skippedProgramCoordinates::add);
    final Set<ArtifactCoordinate> unchangedCoordinates = new LinkedHashSet<>(forcedUnchanged);
    unchangedCoordinates.addAll(layoutPassThroughCoordinates);
    configuredPassThrough.stream()
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .forEach(unchangedCoordinates::add);
    if (!retainedCoordinates.containsAll(unchangedCoordinates)) {
      throw new IOException("Unchanged analysis set contains an elided artifact");
    }
    final List<MavenElisionService.ArtifactSnapshot> candidates =
        eligible.stream()
            .filter(snapshot -> !unchangedCoordinates.contains(snapshot.coordinate()))
            .filter(
                snapshot ->
                    !inventory.classesByArtifact().getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(
                snapshot ->
                    !passThroughIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .sorted(artifactSnapshotOrder())
            .toList();
    final List<MavenElisionService.ArtifactSnapshot> unchangedPrograms =
        inventory.retainedLibraries().stream()
            .filter(
                snapshot ->
                    !inventory.classesByArtifact().getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(snapshot -> !candidates.contains(snapshot))
            .sorted(artifactSnapshotOrder())
            .toList();
    final Set<String> unchangedPassThroughClasses = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : configuredPassThrough) {
      unchangedPassThroughClasses.addAll(
          inventory.classesByArtifact().getOrDefault(snapshot, Set.of()));
    }
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      if (layoutPassThroughCoordinates.contains(snapshot.coordinate())) {
        unchangedPassThroughClasses.addAll(
            inventory.classesByArtifact().getOrDefault(snapshot, Set.of()));
      }
    }
    return new SingleReleaseLayout(
        retainedCoordinates,
        eligible,
        candidates,
        unchangedPrograms,
        skippedProgramCoordinates,
        unchangedPassThroughClasses);
  }

  private static List<Path> fullClasspath(final SingleReleaseInventory inventory) {
    return inventory.artifacts().stream()
        .filter(snapshot -> ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope()))
        .map(
            snapshot ->
                inventory
                    .analysisPaths()
                    .getOrDefault(snapshot, snapshot.filePath().toAbsolutePath().normalize()))
        .toList();
  }

  private static List<JdkPlatformContext.PlatformSnapshot> platformSnapshots(
      final Path javaHome, final int release, final int runtimeRelease) throws IOException {
    final List<JdkPlatformContext.PlatformSnapshot> snapshots = new ArrayList<>(2);
    try (JdkPlatformContext platformContext = new JdkPlatformContext(javaHome)) {
      snapshots.add(platformContext.snapshot(release));
      if (runtimeRelease != release) {
        snapshots.add(platformContext.snapshot(runtimeRelease));
      }
    }
    return List.copyOf(snapshots);
  }

  private static SingleReleaseRootPlan singleReleaseRootPlan(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final List<Path> fullClasspath,
      final PlatformPools pools,
      final TrimAnalysisSession analysisSession,
      final int trimWorkers)
      throws IOException {
    final Set<String> commonRoots = commonRoots(request);
    final Set<String> platformClasses = platformClasses(pools);
    final CommonRootOwners commonRootOwners =
        commonRootOwners(
            commonRoots,
            inventory.ownerByClass(),
            request,
            layout.retainedCoordinates(),
            inventory.classesByArtifact(),
            platformClasses);
    final DynamicRootPlan dynamicRoots =
        dynamicRootPlan(request, inventory, layout, platformClasses);
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots =
        candidateRoots(inventory, layout, commonRootOwners, dynamicRoots);
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedCandidates =
            prepareCandidates(layout, fullClasspath, pools, analysisSession, trimWorkers);
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedPrograms =
            preparePrograms(inventory, layout, fullClasspath, pools, analysisSession, trimWorkers);
    final Set<ArtifactCoordinate> reachableArtifacts =
        new LinkedHashSet<>(commonRootOwners.droppedArtifacts());
    reachableArtifacts.addAll(dynamicRoots.droppedArtifacts());
    return new SingleReleaseRootPlan(
        candidateRoots, preparedCandidates, preparedPrograms, reachableArtifacts);
  }

  private static DynamicRootPlan dynamicRootPlan(
      final TrimRequest request,
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final Set<String> platformClasses)
      throws IOException {
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> rootsByOwner =
        new java.util.LinkedHashMap<>();
    final Set<ArtifactCoordinate> droppedArtifacts = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory.retainedLibraries()) {
      for (final String root : dynamicRoots(request, snapshot.filePath())) {
        final MavenElisionService.ArtifactSnapshot owner = inventory.ownerByClass().get(root);
        if (owner == null) {
          if (request.projectOutputClasses().contains(root) || platformClasses.contains(root)) {
            continue;
          }
          droppedArtifacts.addAll(droppedArtifactCoordinates(inventory, layout));
          continue;
        }
        if (layout.retainedCoordinates().contains(owner.coordinate())) {
          if (layout.eligible().contains(owner)) {
            rootsByOwner.computeIfAbsent(owner, ignored -> new TreeSet<>()).add(root);
          }
        } else {
          droppedArtifacts.add(owner.coordinate());
        }
      }
    }
    return new DynamicRootPlan(rootsByOwner, droppedArtifacts);
  }

  private static Set<ArtifactCoordinate> droppedArtifactCoordinates(
      final SingleReleaseInventory inventory, final SingleReleaseLayout layout) {
    return inventory.artifacts().stream()
        .filter(snapshot -> !layout.retainedCoordinates().contains(snapshot.coordinate()))
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
  }

  private static Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots(
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final CommonRootOwners commonRootOwners,
      final DynamicRootPlan dynamicRoots) {
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots =
        new java.util.LinkedHashMap<>();
    for (final MavenElisionService.ArtifactSnapshot candidate : layout.candidates()) {
      final Set<String> roots =
          new TreeSet<>(inventory.requestedRoots().getOrDefault(candidate, Set.of()));
      roots.addAll(commonRootOwners.byArtifact().getOrDefault(candidate, Set.of()));
      roots.addAll(dynamicRoots.rootsByOwner().getOrDefault(candidate, Set.of()));
      if (roots.isEmpty()) {
        roots.addAll(inventory.classesByArtifact().getOrDefault(candidate, Set.of()));
      }
      candidateRoots.put(candidate, roots);
    }
    return candidateRoots;
  }

  private static Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      prepareCandidates(
          final SingleReleaseLayout layout,
          final List<Path> fullClasspath,
          final PlatformPools pools,
          final TrimAnalysisSession analysisSession,
          final int trimWorkers)
          throws IOException {
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        mapParallel(
            layout.candidates(),
            trimWorkers,
            candidate -> {
              final Path path = candidate.filePath().toAbsolutePath().normalize();
              final List<Path> siblings =
                  fullClasspath.stream().filter(value -> !value.equals(path)).toList();
              return analysisSession.prepareWithUnchangedPassThroughLibraries(
                  path, siblings, pools.compiler(), layout.unchangedPassThroughClasses());
            });
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedCandidates = new java.util.LinkedHashMap<>();
    for (int index = 0; index < layout.candidates().size(); index++) {
      preparedCandidates.put(layout.candidates().get(index), results.get(index));
    }
    return preparedCandidates;
  }

  private static Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
      preparePrograms(
          final SingleReleaseInventory inventory,
          final SingleReleaseLayout layout,
          final List<Path> fullClasspath,
          final PlatformPools pools,
          final TrimAnalysisSession analysisSession,
          final int trimWorkers)
          throws IOException {
    final List<DependencyJarTrimmer.PreparedAnalysis> results =
        mapParallel(
            layout.unchangedPrograms(),
            trimWorkers,
            program -> {
              final Path path =
                  inventory
                      .analysisPaths()
                      .getOrDefault(program, program.filePath().toAbsolutePath().normalize());
              final List<Path> siblings =
                  fullClasspath.stream().filter(value -> !value.equals(path)).toList();
              return layout.skippedProgramCoordinates().contains(program.coordinate())
                  ? analysisSession.prepareUnchangedPassThrough(
                      path, siblings, pools.runtime(), layout.unchangedPassThroughClasses())
                  : analysisSession.prepareWithUnchangedPassThroughLibraries(
                      path, siblings, pools.runtime(), layout.unchangedPassThroughClasses());
            });
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedPrograms = new java.util.LinkedHashMap<>();
    for (int index = 0; index < layout.unchangedPrograms().size(); index++) {
      preparedPrograms.put(layout.unchangedPrograms().get(index), results.get(index));
    }
    return preparedPrograms;
  }

  private static SingleReleaseClosure analyzeSingleReleaseClosure(
      final SingleReleaseInventory inventory,
      final SingleReleaseLayout layout,
      final SingleReleaseRootPlan roots,
      final int trimWorkers)
      throws IOException {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> finalAnalyses =
        new java.util.LinkedHashMap<>();
    final Set<ArtifactCoordinate> reachableArtifacts =
        new LinkedHashSet<>(roots.reachableArtifacts());
    int analysisRuns = 0;
    boolean rootsChanged;
    do {
      rootsChanged = false;
      final List<
              Map.Entry<
                  MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          programEntries = List.copyOf(roots.preparedPrograms().entrySet());
      final List<DependencyJarTrimmer.TrimAnalysis> programAnalyses =
          mapParallel(
              programEntries,
              trimWorkers,
              entry -> entry.getValue().analyze(inventory.classesByArtifact().get(entry.getKey())));
      analysisRuns += programAnalyses.size();
      for (int index = 0; index < programEntries.size(); index++) {
        final Map.Entry<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            entry = programEntries.get(index);
        final DependencyJarTrimmer.TrimAnalysis analysis = programAnalyses.get(index);
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                inventory.ownerByClass(),
                layout.candidates(),
                roots.candidateRoots(),
                reachableArtifacts,
                layout.retainedCoordinates(),
                entry.getKey());
      }
      finalAnalyses.clear();
      final List<
              Map.Entry<
                  MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          candidateEntries = List.copyOf(roots.preparedCandidates().entrySet());
      final List<DependencyJarTrimmer.TrimAnalysis> candidateAnalyses =
          mapParallel(
              candidateEntries,
              trimWorkers,
              entry -> entry.getValue().analyze(roots.candidateRoots().get(entry.getKey())));
      analysisRuns += candidateAnalyses.size();
      for (int index = 0; index < candidateEntries.size(); index++) {
        final MavenElisionService.ArtifactSnapshot candidate = candidateEntries.get(index).getKey();
        final DependencyJarTrimmer.TrimAnalysis analysis = candidateAnalyses.get(index);
        finalAnalyses.put(candidate.coordinate(), analysis);
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                inventory.ownerByClass(),
                layout.candidates(),
                roots.candidateRoots(),
                reachableArtifacts,
                layout.retainedCoordinates(),
                candidate);
      }
    } while (rootsChanged);
    return new SingleReleaseClosure(finalAnalyses, reachableArtifacts, analysisRuns);
  }

  private static int analysisRelease(
      final TrimRequest request, final Path javaHome, final int runtimeRelease) throws IOException {
    if (!request.trimEnabled()) {
      return runtimeRelease;
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.platformReleaseOptions(request.project(), request.session());
    return releaseFromOptions(compilerOptions, javaHome);
  }

  private static ServiceProviderInventory serviceProviderInventory(
      final EffectiveOutputPlan outputPlan, final List<CandidateWork> candidates)
      throws IOException {
    final Map<ArtifactCoordinate, CandidateWork> candidatesByCoordinate = new java.util.HashMap<>();
    candidates.forEach(
        candidate -> candidatesByCoordinate.put(candidate.snapshot().coordinate(), candidate));
    final Set<String> ownedClasses = new HashSet<>();
    final Set<String> retainedClasses = new HashSet<>();
    final Path projectionDirectory = analysisLibraryDirectory(outputPlan.prepared().project());
    for (final MavenElisionService.ArtifactSnapshot snapshot :
        outputPlan.prepared().resolvedSnapshots()) {
      if (!JAR_TYPE.equals(snapshot.coordinate().type())) {
        continue;
      }
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final Set<String> logicalClasses = logicalClassNames(source);
      ownedClasses.addAll(logicalClasses);
      if (!outputPlan.retainedCoordinates().contains(snapshot.coordinate())) {
        continue;
      }
      final CandidateWork candidate = candidatesByCoordinate.get(snapshot.coordinate());
      if (candidate != null) {
        candidate.analysis().retainedClasses().stream()
            .map(name -> name.replace('/', '.'))
            .forEach(retainedClasses::add);
      } else if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)) {
        final Path projection =
            MultiReleaseLibraryProjection.create(
                source,
                snapshot.coordinate(),
                projectionDirectory,
                outputPlan.analysis().compilerRelease());
        retainedClasses.addAll(classNames(projection));
      } else {
        retainedClasses.addAll(logicalClasses);
      }
    }
    return new ServiceProviderInventory(ownedClasses, retainedClasses);
  }

  private static Set<String> removedServiceProviders(
      final CandidateWork candidate,
      final ScanInputs scanInputs,
      final ServiceProviderInventory inventory)
      throws IOException {
    final Path source = candidate.snapshot().filePath().toAbsolutePath().normalize();
    final DependencyDynamicRoots.RootScan scan = scanInputs.dynamicRootScans().get(source);
    if (scan == null) {
      throw new IOException(
          "Missing service descriptor scan for " + candidate.snapshot().coordinate());
    }
    final Set<String> removed = new HashSet<>();
    for (final DependencyDynamicRoots.ServiceDescriptor descriptor : scan.serviceDescriptors()) {
      for (final String provider : descriptor.providers()) {
        if (inventory.ownedClasses().contains(provider)
            && !inventory.retainedClasses().contains(provider)) {
          removed.add(provider);
        }
      }
    }
    return Set.copyOf(removed);
  }

  static void validateAnalysisInventory(final List<MavenElisionService.ArtifactSnapshot> inventory)
      throws IOException {
    final Set<ArtifactCoordinate> coordinates = new HashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
      if (!coordinates.add(snapshot.coordinate())) {
        throw new IOException(
            "Duplicate JAR identity in analysis inventory: " + snapshot.coordinate());
      }
      if (snapshot.filePath() == null || !Files.isRegularFile(snapshot.filePath())) {
        throw new IOException("Incomplete JAR analysis inventory: " + snapshot.coordinate());
      }
    }
  }

  private static Map<MavenElisionService.ArtifactSnapshot, Path> analysisPaths(
      final TrimRequest request, final List<MavenElisionService.ArtifactSnapshot> inventory)
      throws IOException {
    final Map<MavenElisionService.ArtifactSnapshot, Path> result = new java.util.LinkedHashMap<>();
    final int runtimeRelease = Runtime.version().feature();
    final Path projectionDirectory = analysisLibraryDirectory(request.project());
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
      if (!ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())) {
        continue;
      }
      final boolean multiRelease =
          MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath());
      final boolean moduleInfo =
          MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
      if (multiRelease || moduleInfo) {
        if (request.retainedCoordinates().contains(snapshot.coordinate())) {
          passThroughCoordinate(request, snapshot);
        }
        result.put(
            snapshot,
            MultiReleaseLibraryProjection.create(
                snapshot.filePath(), snapshot.coordinate(), projectionDirectory, runtimeRelease));
      }
    }
    return result;
  }

  private static boolean passThroughCoordinate(
      final TrimRequest request, final MavenElisionService.ArtifactSnapshot snapshot)
      throws IOException {
    final DependencyDynamicRoots.RootScan rootScan =
        request.scanInputs().dynamicRootScans().get(snapshot.filePath());
    final boolean nativeImageFallback = rootScan != null && rootScan.requiresPassThrough();
    final boolean multiRelease =
        MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath());
    final boolean moduleInfo =
        MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
    if (!request.retainedCoordinates().contains(snapshot.coordinate())) {
      return multiRelease || moduleInfo || nativeImageFallback;
    }
    if (moduleInfo && request.failOnUnsupportedModuleInfo()) {
      throw new IOException(
          "Unsupported root module descriptor in retained classpath JAR: " + snapshot.coordinate());
    }
    return nativeImageFallback
        || moduleInfo
        || (multiRelease && MRJAR_PASS_THROUGH.equals(request.mrjarStrategy()));
  }

  static Map<MavenElisionService.ArtifactSnapshot, Set<String>> validateDiscoveredRoots(
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final List<MavenElisionService.ArtifactSnapshot> inventory,
      final Map<Path, Set<String>> classesByPath)
      throws IOException {
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> result =
        new java.util.LinkedHashMap<>();
    for (final Map.Entry<ArtifactRootKey, Set<String>> entry : discoveredRoots.entrySet()) {
      final ArtifactRootKey key = entry.getKey();
      if (key.sha256() == null || !key.sha256().matches("[0-9a-f]{64}")) {
        throw new IOException("Invalid discovered-root artifact digest: " + key.coordinate());
      }
      final MavenElisionService.ArtifactSnapshot snapshot =
          inventory.stream()
              .filter(candidate -> candidate.coordinate().equals(key.coordinate()))
              .filter(
                  candidate -> candidate.filePath().toAbsolutePath().normalize().equals(key.path()))
              .findFirst()
              .orElseThrow(
                  () ->
                      new IOException(
                          "Discovered roots do not match an inventory artifact: "
                              + key.coordinate()));
      if (!ArtifactDigests.read(key.path()).sha256().equals(key.sha256())) {
        throw new IOException("Discovered-root input digest changed: " + key.coordinate());
      }
      final Set<String> classes = classesByPath.get(key.path());
      if (classes == null || !classes.containsAll(entry.getValue())) {
        throw new IOException(
            "Discovered root is not indexed in its owning JAR: " + key.coordinate());
      }
      result.computeIfAbsent(snapshot, ignored -> new TreeSet<>()).addAll(entry.getValue());
    }
    return result;
  }

  static Set<String> commonRoots(final TrimRequest request) {
    final Set<String> roots = new LinkedHashSet<>(request.trace().loadedClassesDotFormat());
    roots.addAll(request.sourceRoots());
    roots.addAll(request.bytecodeRoots());
    request.explicitRoots().forEach(roots::add);
    return roots;
  }

  private static CommonRootOwners commonRootOwners(
      final Set<String> roots,
      final Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass,
      final TrimRequest request,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classesByArtifact,
      final Set<String> platformClasses)
      throws IOException {
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> rootsByArtifact =
        new java.util.LinkedHashMap<>();
    final Set<ArtifactCoordinate> droppedArtifacts = new LinkedHashSet<>();
    final Set<String> strictRoots = new HashSet<>();
    request.sourceRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    request.bytecodeRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    request.explicitRoots().forEach(root -> strictRoots.add(root.replace('/', '.')));
    for (final String rawRoot : roots) {
      final String root = rawRoot.replace('/', '.');
      final MavenElisionService.ArtifactSnapshot owner = ownerByClass.get(root);
      if (owner == null) {
        if (request.projectOutputClasses().contains(root) || platformClasses.contains(root)) {
          continue;
        }
        if (strictRoots.contains(root)) {
          throw new IOException("Required class root has no recognized owner: " + root);
        }
        continue;
      }
      if (!retainedCoordinates.contains(owner.coordinate())) {
        droppedArtifacts.add(owner.coordinate());
        continue;
      }
      if (classesByArtifact.getOrDefault(owner, Set.of()).contains(root)) {
        rootsByArtifact.computeIfAbsent(owner, ignored -> new TreeSet<>()).add(root);
      }
    }
    return new CommonRootOwners(rootsByArtifact, droppedArtifacts);
  }

  private static Set<String> platformClasses(final PlatformPools pools) {
    final Set<String> result = new HashSet<>();
    pools.compiler().classNames().forEachRemaining(name -> result.add(name.replace('/', '.')));
    pools.runtime().classNames().forEachRemaining(name -> result.add(name.replace('/', '.')));
    return Set.copyOf(result);
  }

  static Set<String> dynamicRoots(final TrimRequest request, final Path path) throws IOException {
    final DependencyDynamicRoots.RootScan scan = request.scanInputs().dynamicRootScans().get(path);
    if (scan == null) {
      throw new IOException("Missing dynamic-root scan for full inventory JAR: " + path);
    }
    final DependencyDynamicRoots.EffectiveRoots effective =
        scan.effectiveRoots(
            request.provenServiceInterfaces(), request.conservativeServiceLoaderRoots());
    return effective.roots().stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toSet());
  }

  private static boolean collectReachableClasses(
      final Set<String> reachable,
      final Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass,
      final List<MavenElisionService.ArtifactSnapshot> candidates,
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final MavenElisionService.ArtifactSnapshot source) {
    boolean changed = false;
    for (final String reachableName : reachable) {
      final String name = reachableName.replace('/', '.');
      final MavenElisionService.ArtifactSnapshot owner = ownerByClass.get(name);
      if (owner == null || owner.equals(source)) {
        continue;
      }
      final ArtifactCoordinate coordinate = owner.coordinate();
      if (retainedCoordinates.contains(coordinate)) {
        if (candidates.contains(owner)) {
          changed |= candidateRoots.get(owner).add(name);
        }
      } else {
        reachableArtifacts.add(coordinate);
      }
    }
    return changed;
  }

  static InMemoryAnalysis inMemoryResult(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses,
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final int analysisRuns,
      final int compilerRelease,
      final int runtimeRelease,
      final Path javaHome,
      final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots,
      final Map<ArtifactCoordinate, Set<String>> upperTierClasses) {
    final Map<ArtifactCoordinate, Set<String>> rootsByCoordinate = new java.util.LinkedHashMap<>();
    roots.forEach((snapshot, values) -> rootsByCoordinate.put(snapshot.coordinate(), values));
    return new InMemoryAnalysis(
        analyses,
        rootsByCoordinate,
        reachableArtifacts,
        analysisRuns,
        compilerRelease,
        runtimeRelease,
        javaHome,
        platformSnapshots.stream()
            .sorted(Comparator.comparingInt(JdkPlatformContext.PlatformSnapshot::effectiveRelease))
            .map(JdkPlatformContext.PlatformSnapshot::identity)
            .toList(),
        platformSnapshots.stream()
            .map(JdkPlatformContext.PlatformSnapshot::effectiveRelease)
            .distinct()
            .sorted()
            .toList(),
        upperTierClasses);
  }

  private static Map<ArtifactCoordinate, Set<String>> immutableSetMap(
      final Map<ArtifactCoordinate, Set<String>> values) {
    final Map<ArtifactCoordinate, Set<String>> result = new java.util.LinkedHashMap<>();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry ->
                result.put(
                    entry.getKey(),
                    java.util.Collections.unmodifiableSet(new TreeSet<>(entry.getValue()))));
    return java.util.Collections.unmodifiableMap(result);
  }

  private static Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> immutableAnalysisMap(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> values) {
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> result =
        new java.util.LinkedHashMap<>();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(entry -> result.put(entry.getKey(), entry.getValue()));
    return java.util.Collections.unmodifiableMap(result);
  }

  private static void verifyAnalysisPlatform(
      final MavenElisionService.EffectiveAnalysis effective,
      final int compilerRelease,
      final int runtimeRelease,
      final Path javaHome)
      throws IOException {
    final InMemoryAnalysis analysis = effective.trimAnalysis();
    if (compilerRelease != analysis.compilerRelease()
        || runtimeRelease != analysis.runtimeRelease()
        || !javaHome.toAbsolutePath().normalize().equals(analysis.javaHome())) {
      throw new IOException("Compiler or JDK context changed after effective analysis");
    }
  }

  private static Set<ArtifactCoordinate> classlessRetainedCoordinates(
      final List<MavenElisionService.ArtifactSnapshot> inventory,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact,
      final Set<ArtifactCoordinate> retained) {
    final Map<Path, Set<String>> byPath = classesByPath(classesByArtifact);
    return inventory.stream()
        .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
        .filter(snapshot -> retained.contains(snapshot.coordinate()))
        .filter(
            snapshot ->
                byPath
                    .getOrDefault(snapshot.filePath().toAbsolutePath().normalize(), Set.of())
                    .isEmpty())
        .map(MavenElisionService.ArtifactSnapshot::coordinate)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
  }

  private static TrimResult trimPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext)
      throws IOException, MojoFailureException {
    return trimPrepared(request, release, runtimeRelease, platformContext, null);
  }

  private static TrimResult trimPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext,
      final EffectiveOutputPlan effectiveOutput)
      throws IOException, MojoFailureException {
    if (effectiveOutput != null) {
      return trimEffectivePrepared(
          request, release, runtimeRelease, platformContext, effectiveOutput);
    }
    return trimDirectPrepared(request, release, runtimeRelease, platformContext);
  }

  private static TrimResult trimEffectivePrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext,
      final EffectiveOutputPlan effectiveOutput)
      throws IOException, MojoFailureException {
    final MavenProject project = request.project();
    final PassThroughPlan passThrough = passThroughPlan(request);
    final CandidatePlan plan =
        effectiveCandidatePlan(
            project,
            passThrough.retainedLibraries(),
            passThrough.retained(),
            request.scanInputs().classIndex().classesByArtifact(),
            effectiveOutput);
    final List<Path> retainedInputPaths =
        fullJarInventory(request.candidates()).stream()
            .map(MavenElisionService.ArtifactSnapshot::filePath)
            .toList();
    final List<CandidateWork> work = plan.work();
    final Path manifest = cacheManifestPath(project);
    final long cacheStart = System.nanoTime();
    final FingerprintSnapshot fingerprint =
        fingerprint(
            work,
            retainedInputPaths,
            passThrough.skippedArtifactIdentities(),
            new FingerprintOptions(
                runtimeRelease,
                release,
                CACHE_SCHEMA_VERSION,
                ENGINE_VERSION,
                platformContext,
                effectiveOutput.analysis().analyzedTiers(),
                effectiveCacheContext(request, effectiveOutput)));
    verifyEffectiveInputs(effectiveOutput, fingerprint);
    final List<String> platformIdentities =
        fingerprint.platformSnapshots().stream()
            .map(JdkPlatformContext.PlatformSnapshot::identity)
            .toList();
    if (!platformIdentities.equals(effectiveOutput.analysis().platformIdentities())) {
      throw new IOException("JDK platform identity changed after effective analysis");
    }
    final String completeFingerprint = fingerprint.value();
    final Path generation = generationPath(project, completeFingerprint);
    work.forEach(
        candidate -> candidate.output(generation.resolve(candidate.output().getFileName())));
    assignEffectiveAnalyses(plan, effectiveOutput.analysis());
    final TrimResult cached =
        loadCache(
            manifest,
            completeFingerprint,
            fingerprint.inputDigests(),
            work,
            passThrough.multiReleaseCoordinates(),
            passThrough.moduleInfoCoordinates(),
            passThrough.configuredCoordinates(),
            cacheStart);
    if (cached != null) {
      verifyEffectiveInputs(effectiveOutput, fingerprint);
      return cached;
    }
    return publishEffectiveOutputs(
        new EffectivePublication(
            effectiveOutput,
            work,
            fingerprint,
            manifest,
            completeFingerprint,
            passThrough.multiReleaseCoordinates(),
            passThrough.moduleInfoCoordinates(),
            passThrough.configuredCoordinates(),
            effectiveOutput.analysis().analysisRuns()));
  }

  private static TrimResult trimDirectPrepared(
      final TrimRequest request,
      final int release,
      final int runtimeRelease,
      final JdkPlatformContext platformContext)
      throws IOException, MojoFailureException {
    if (request.trimEnabled() && MRJAR_VERTICAL_SHADING.equals(request.mrjarStrategy())) {
      for (final MavenElisionService.ArtifactSnapshot snapshot :
          passThroughPlan(request).retained()) {
        if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())) {
          throw new IOException(
              "Vertical-shading MRJAR output requires tier-aware effective analysis: "
                  + snapshot.coordinate());
        }
      }
    }
    final MavenProject project = request.project();
    final ScanInputs scanInputs = request.scanInputs();
    final TraceData trace = request.trace();
    final Set<String> sourceRoots = request.sourceRoots();
    final Set<String> bytecodeRoots = request.bytecodeRoots();
    final List<String> explicitRoots = request.explicitRoots();

    final Set<String> allRoots = new LinkedHashSet<>(trace.loadedClassesDotFormat());
    allRoots.addAll(sourceRoots);
    allRoots.addAll(bytecodeRoots);
    allRoots.addAll(explicitRoots);
    final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact =
        scanInputs.classIndex().classesByArtifact();
    final PassThroughPlan passThroughPlan = passThroughPlan(request);
    final List<MavenElisionService.ArtifactSnapshot> retainedLibraries =
        passThroughPlan.retainedLibraries();
    final List<MavenElisionService.ArtifactSnapshot> retained = passThroughPlan.retained();
    final Set<String> skippedArtifactIdentities = passThroughPlan.skippedArtifactIdentities();
    final List<ArtifactCoordinate> multiReleasePassthroughCoordinates =
        passThroughPlan.multiReleaseCoordinates();
    final List<ArtifactCoordinate> moduleInfoPassthroughCoordinates =
        passThroughPlan.moduleInfoCoordinates();
    final List<ArtifactCoordinate> configuredPassThroughCoordinates =
        passThroughPlan.configuredCoordinates();
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    final CandidatePlan plan =
        candidatePlan(
            project, retainedLibraries, retained, scanInputs, classesByArtifact, allRoots);
    final List<Path> retainedInputPaths = plan.retainedInputPaths();
    final List<CandidateWork> work = plan.work();
    final Path cacheManifestPath = cacheManifestPath(project);
    final long cacheStart = System.nanoTime();
    final FingerprintSnapshot fingerprintSnapshot =
        fingerprint(
            work,
            retainedInputPaths,
            skippedArtifactIdentities,
            new FingerprintOptions(
                runtimeRelease,
                release,
                CACHE_SCHEMA_VERSION,
                ENGINE_VERSION,
                platformContext,
                List.of(release, runtimeRelease),
                null));
    final String completeFingerprint = fingerprintSnapshot.value();
    final TrimResult cached =
        loadCache(
            cacheManifestPath,
            completeFingerprint,
            fingerprintSnapshot.inputDigests(),
            work,
            multiReleasePassthroughCoordinates,
            moduleInfoPassthroughCoordinates,
            configuredPassThroughCoordinates,
            cacheStart);
    if (cached != null) {
      return cached;
    }
    final Path analysisLibraryDirectory = analysisLibraryDirectory(project);
    final PlatformPools platformPools =
        readPlatformPools(fingerprintSnapshot.platformSnapshots(), release, runtimeRelease);
    final int analysisRuns =
        analyze(
            plan,
            passThroughPlan,
            analysisLibraryDirectory,
            runtimeRelease,
            platformPools,
            request.trimWorkers());

    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final Map<CandidateWork, CacheEntry> entriesByCandidate = new java.util.HashMap<>();
    try (PreparedOutputCleanup preparedOutputCleanup = new PreparedOutputCleanup(sanitizer)) {
      final List<CandidateWork> toSanitize = new ArrayList<>();
      for (final CandidateWork candidate : work) {
        final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
        if (analysis == null) {
          continue;
        }
        if (analysis.retainedClasses().size() == analysis.totalClasses()) {
          entriesByCandidate.put(
              candidate, cacheEntry(candidate, null, fingerprintSnapshot.inputDigests()));
          continue;
        }
        toSanitize.add(candidate);
      }
      final List<PendingOutput> prepared =
          mapParallel(
              toSanitize,
              request.trimWorkers(),
              candidate -> {
                final ArchiveSanitizer.PreparedOutput staged =
                    sanitizer.prepareWithProvenance(
                        candidate.snapshot().filePath(),
                        candidate.output(),
                        candidate.snapshot().coordinate(),
                        candidate.analysis(),
                        requiredInputDigest(
                            fingerprintSnapshot.inputDigests(), candidate.snapshot().filePath()));
                return preparedOutputCleanup.track(new PendingOutput(candidate, staged));
              },
              preparedOutputCleanup);
      final List<ArtifactTrimRecord> publishedRecords =
          publishOutputs(
              prepared.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
      for (int index = 0; index < prepared.size(); index++) {
        final PendingOutput pending = prepared.get(index);
        final ArtifactTrimRecord record = publishedRecords.get(index);
        records.add(record);
        entriesByCandidate.put(
            pending.candidate(),
            cacheEntry(pending.candidate(), record, fingerprintSnapshot.inputDigests()));
      }
    }
    final List<CacheEntry> cacheEntries = new ArrayList<>(work.size());
    for (final CandidateWork candidate : work) {
      final CacheEntry entry = entriesByCandidate.get(candidate);
      if (entry == null) {
        throw new IOException("Missing trim-cache entry for " + candidate.snapshot().coordinate());
      }
      cacheEntries.add(entry);
    }
    storeCache(
        cacheManifestPath,
        new CacheManifest(
            CACHE_SCHEMA_VERSION, CACHE_FORMAT_ID, completeFingerprint, cacheEntries));
    return new TrimResult(
        records,
        multiReleasePassthroughCoordinates,
        moduleInfoPassthroughCoordinates,
        configuredPassThroughCoordinates,
        0,
        0L,
        analysisRuns);
  }

  @SuppressWarnings({"PMD.ExceptionAsFlowControl", "PMD.AvoidCatchingGenericException"})
  // Cleanup can fail after installation, so catch and roll back the new generation.
  private static TrimResult publishEffectiveOutputs(final EffectivePublication publication)
      throws IOException {
    final EffectiveOutputPlan effectiveOutput = publication.outputPlan();
    final List<CandidateWork> work = publication.work();
    final FingerprintSnapshot fingerprint = publication.fingerprint();
    final Path manifest = publication.manifest();
    final String completeFingerprint = publication.completeFingerprint();
    final MavenProject project = effectiveOutput.prepared().project();
    final Path generation = generationPath(project, completeFingerprint);
    final Path generationParent = generation.getParent();
    if (generationParent == null) {
      throw new IOException("Trim generation has no parent directory: " + generation);
    }
    Files.createDirectories(generationParent);
    final Path manifestParent = manifest.getParent();
    if (manifestParent == null) {
      throw new IOException("Trim cache manifest has no parent directory: " + manifest);
    }
    Files.createDirectories(manifestParent);
    final Path stagingRoot = manifestParent.resolve(".staging");
    Files.createDirectories(stagingRoot);
    final Path stagedGeneration = Files.createTempDirectory(stagingRoot, "trim-");
    final Path stagedManifest =
        Files.createTempFile(manifestParent, ".trim-cache-stage-", ".json.tmp");
    final EffectiveOutputStaging staging =
        new EffectiveOutputStaging(stagedGeneration, stagedManifest);
    TrimOutputGenerationCommitHandle generationCommit = null;
    try {
      try (staging) {
        final PreparedEffectiveOutputs preparedOutputs =
            staging.prepareOutputs(
                work,
                fingerprint.inputDigests(),
                effectiveOutput,
                effectiveOutput.prepared().options().trimWorkers());
        final List<CacheEntry> entries = new ArrayList<>(work.size());
        for (final CandidateWork candidate : work) {
          final CacheEntry entry = preparedOutputs.entries().get(candidate);
          if (entry == null) {
            throw new IOException(
                "Missing effective trim cache entry: " + candidate.snapshot().coordinate());
          }
          entries.add(entry);
        }
        JSON.writeValue(
            stagedManifest.toFile(),
            new CacheManifest(CACHE_SCHEMA_VERSION, CACHE_FORMAT_ID, completeFingerprint, entries));
        verifyEffectiveInputs(effectiveOutput, fingerprint);
        generationCommit =
            TrimOutputGenerationPublisher.publish(
                stagedGeneration, generation, stagedManifest, manifest, effectiveOutput.move());
        return new TrimResult(
            preparedOutputs.records(),
            publication.multiRelease(),
            publication.moduleInfo(),
            publication.configured(),
            0,
            0L,
            publication.analysisRuns(),
            generationCommit);
      }
    } catch (final IOException | RuntimeException failure) {
      if (generationCommit != null) {
        try {
          generationCommit.close();
        } catch (final IOException cleanupFailure) {
          failure.addSuppressed(cleanupFailure);
        }
      }
      throw failure;
    }
  }

  private static void deleteTree(final Path root) throws IOException {
    if (!Files.exists(root)) {
      return;
    }
    try (var paths = Files.walk(root)) {
      for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }

  private static int analyze(
      final CandidatePlan candidatePlan,
      final PassThroughPlan passThroughPlan,
      final Path analysisLibraryDirectory,
      final int runtimeRelease,
      final PlatformPools platformPools,
      final int trimWorkers)
      throws IOException {
    final AnalysisLibraries libraries =
        analysisLibraries(passThroughPlan, analysisLibraryDirectory, runtimeRelease);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final TrimAnalysisSession session = new TrimAnalysisSession(trimmer);
    validateUniqueAnalysisClasses(candidatePlan, libraries.skippedPrograms());
    final int passThroughRuns =
        analyzePassThroughPrograms(
            candidatePlan, libraries, session, platformPools.runtime(), trimWorkers);
    return passThroughRuns
        + analyzeCandidateFixedPoint(
            candidatePlan, libraries, session, platformPools.compiler(), trimWorkers);
  }

  private static AnalysisLibraries analysisLibraries(
      final PassThroughPlan passThroughPlan,
      final Path analysisLibraryDirectory,
      final int runtimeRelease)
      throws IOException {
    final List<Path> analysisLibraries = new ArrayList<>();
    final List<SkippedProgram> skippedPrograms = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot :
        passThroughPlan.retainedLibraries()) {
      if (passThroughPlan
          .skippedArtifactIdentities()
          .contains(artifactIdentity(snapshot.coordinate()))) {
        final boolean multiRelease =
            passThroughPlan
                .multiReleaseIdentities()
                .contains(artifactIdentity(snapshot.coordinate()));
        final boolean rootModuleDescriptor =
            MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
        final Path analysisPath =
            multiRelease || rootModuleDescriptor
                ? MultiReleaseLibraryProjection.create(
                    snapshot.filePath(),
                    snapshot.coordinate(),
                    analysisLibraryDirectory,
                    runtimeRelease)
                : snapshot.filePath();
        analysisLibraries.add(analysisPath);
        skippedPrograms.add(new SkippedProgram(analysisPath, classNames(analysisPath)));
      } else {
        analysisLibraries.add(snapshot.filePath());
      }
    }
    final Set<String> unchangedPassThroughClassNames = new LinkedHashSet<>();
    skippedPrograms.stream()
        .flatMap(program -> program.classNames().stream())
        .forEach(unchangedPassThroughClassNames::add);
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      for (final Path siblingPath : analysisLibraries) {
        if (siblingPath.equals(skippedProgram.path())) {
          continue;
        }
        final Set<String> ambiguousNames = new HashSet<>(skippedProgram.classNames());
        ambiguousNames.retainAll(classNames(siblingPath));
        if (!ambiguousNames.isEmpty()) {
          throw new IOException(
              "Duplicate class ownership makes pass-through unresolved-link tolerance ambiguous: "
                  + ambiguousNames);
        }
      }
    }
    return new AnalysisLibraries(
        analysisLibraries, skippedPrograms, unchangedPassThroughClassNames);
  }

  private static void validateUniqueAnalysisClasses(
      final CandidatePlan candidatePlan, final List<SkippedProgram> skippedPrograms)
      throws IOException {
    final Set<String> allCandidateClasses = new HashSet<>(candidatePlan.ownerByClass().keySet());
    for (final SkippedProgram skippedProgram : skippedPrograms) {
      for (final String className : skippedProgram.classNames()) {
        if (!allCandidateClasses.add(className)) {
          throw new IOException(
              "Duplicate class across retained dependency JARs makes library order ambiguous: "
                  + className);
        }
      }
    }
  }

  private static int analyzePassThroughPrograms(
      final CandidatePlan candidatePlan,
      final AnalysisLibraries libraries,
      final TrimAnalysisSession analysisSession,
      final ClassPool runtimePlatform,
      final int trimWorkers)
      throws IOException {
    final List<SkippedProgram> skipped = libraries.skippedPrograms();
    if (skipped.isEmpty()) {
      return 0;
    }
    final List<DependencyJarTrimmer.TrimAnalysis> analyses =
        mapParallel(
            skipped,
            trimWorkers,
            skippedProgram -> {
              final List<Path> siblings =
                  libraries.paths().stream()
                      .filter(path -> !path.equals(skippedProgram.path()))
                      .toList();
              final DependencyJarTrimmer.PreparedAnalysis prepared =
                  analysisSession.prepareUnchangedPassThrough(
                      skippedProgram.path(),
                      siblings,
                      runtimePlatform,
                      libraries.passThroughClassNames());
              return prepared.analyze(skippedProgram.classNames());
            });
    int analysisRuns = 0;
    for (final DependencyJarTrimmer.TrimAnalysis analysis : analyses) {
      analysisRuns++;
      for (final String linkedName : analysis.reachableLibraryClasses()) {
        final String dottedName = linkedName.replace('/', '.');
        for (final CandidateWork owner :
            candidatePlan.ownersByClass().getOrDefault(dottedName, List.of())) {
          owner.roots().add(dottedName);
        }
      }
    }
    return analysisRuns;
  }

  private static int analyzeCandidateFixedPoint(
      final CandidatePlan candidatePlan,
      final AnalysisLibraries libraries,
      final TrimAnalysisSession analysisSession,
      final ClassPool platform,
      final int trimWorkers)
      throws IOException {
    int analysisRuns = 0;
    final List<CandidateWork> work = candidatePlan.work();
    final List<DependencyJarTrimmer.PreparedAnalysis> preparedList =
        mapParallel(
            work,
            trimWorkers,
            candidate -> {
              final List<Path> siblings =
                  libraries.paths().stream()
                      .filter(path -> !path.equals(candidate.snapshot().filePath()))
                      .toList();
              return analysisSession.prepareWithUnchangedPassThroughLibraries(
                  candidate.snapshot().filePath(),
                  siblings,
                  platform,
                  libraries.passThroughClassNames());
            });
    final Map<CandidateWork, DependencyJarTrimmer.PreparedAnalysis> candidateAnalyses =
        new java.util.HashMap<>();
    for (int index = 0; index < work.size(); index++) {
      candidateAnalyses.put(work.get(index), preparedList.get(index));
    }
    boolean rootsChanged;
    do {
      rootsChanged = false;
      final List<DependencyJarTrimmer.TrimAnalysis> roundAnalyses =
          mapParallel(
              work,
              trimWorkers,
              candidate -> candidateAnalyses.get(candidate).analyze(candidate.roots()));
      for (int index = 0; index < work.size(); index++) {
        final CandidateWork candidate = work.get(index);
        final DependencyJarTrimmer.TrimAnalysis analysis = roundAnalyses.get(index);
        analysisRuns++;
        candidate.analysis(analysis);
        for (final String linkedName : analysis.reachableLibraryClasses()) {
          final String dottedName = linkedName.replace('/', '.');
          for (final CandidateWork owner :
              candidatePlan.ownersByClass().getOrDefault(dottedName, List.of())) {
            if (owner != candidate && owner.roots().add(dottedName)) {
              rootsChanged = true;
            }
          }
        }
      }
    } while (rootsChanged);
    return analysisRuns;
  }

  static Path analysisLibraryDirectory(final MavenProject project) {
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of(DEFAULT_BUILD_DIRECTORY, ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize();
  }

  static PassThroughPlan passThroughPlan(final TrimRequest request) throws IOException {
    final List<MavenElisionService.ArtifactSnapshot> retainedLibraries =
        request.candidates().stream()
            .filter(
                snapshot ->
                    JAR_TYPE.equals(snapshot.coordinate().type())
                        && TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())
                        && request.retainedCoordinates().contains(snapshot.coordinate()))
            .toList();
    final List<MavenElisionService.ArtifactSnapshot> multiRelease = new ArrayList<>();
    final List<MavenElisionService.ArtifactSnapshot> moduleInfo = new ArrayList<>();
    final List<MavenElisionService.ArtifactSnapshot> nativeImageFallback = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      final DependencyDynamicRoots.RootScan rootScan =
          request.scanInputs().dynamicRootScans().get(snapshot.filePath());
      if (rootScan != null && rootScan.requiresPassThrough()) {
        nativeImageFallback.add(snapshot);
      }
      if (MultiReleaseClassInventory.hasUnsupportedVersionedClasses(snapshot.filePath())
          && MRJAR_PASS_THROUGH.equals(request.mrjarStrategy())) {
        multiRelease.add(snapshot);
      }
      if (MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath())) {
        if (request.failOnUnsupportedModuleInfo()) {
          throw new IOException(
              "Unsupported root module descriptor in retained classpath JAR: "
                  + snapshot.coordinate());
        }
        moduleInfo.add(snapshot);
      }
    }
    final List<MavenElisionService.ArtifactSnapshot> configured =
        parsePassThroughArtifacts(request.explicitPassThroughCoordinates(), retainedLibraries);
    final Set<String> multiReleaseIdentities = identities(multiRelease);
    final Set<String> moduleInfoIdentities = identities(moduleInfo);
    final List<MavenElisionService.ArtifactSnapshot> configuredOnly =
        configured.stream()
            .filter(
                snapshot ->
                    !multiReleaseIdentities.contains(artifactIdentity(snapshot.coordinate()))
                        && !moduleInfoIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    final Set<String> skippedIdentities = new LinkedHashSet<>(multiReleaseIdentities);
    skippedIdentities.addAll(moduleInfoIdentities);
    skippedIdentities.addAll(identities(configured));
    skippedIdentities.addAll(identities(nativeImageFallback));
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      final DependencyDynamicRoots.RootScan scan =
          request.scanInputs().dynamicRootScans().get(snapshot.filePath());
      if (scan != null) {
        skippedIdentities.add("native-image-policy:" + scan.nativeImagePolicy());
      }
    }
    final List<MavenElisionService.ArtifactSnapshot> retained =
        retainedLibraries.stream()
            .filter(
                snapshot -> !skippedIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    return new PassThroughPlan(
        retainedLibraries,
        retained,
        multiReleaseIdentities,
        moduleInfoIdentities,
        skippedIdentities,
        multiRelease.stream().map(MavenElisionService.ArtifactSnapshot::coordinate).toList(),
        moduleInfo.stream().map(MavenElisionService.ArtifactSnapshot::coordinate).toList(),
        configuredOnly.stream().map(MavenElisionService.ArtifactSnapshot::coordinate).toList());
  }

  private static CandidatePlan candidatePlan(
      final MavenProject project,
      final List<MavenElisionService.ArtifactSnapshot> retainedLibraries,
      final List<MavenElisionService.ArtifactSnapshot> retained,
      final ScanInputs scanInputs,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact,
      final Set<String> allRoots)
      throws IOException {
    final List<Path> retainedInputPaths =
        retainedLibraries.stream().map(MavenElisionService.ArtifactSnapshot::filePath).toList();
    final Set<String> retainedDynamicRoots = new HashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      final DependencyDynamicRoots.RootScan scan =
          scanInputs.dynamicRootScans().get(snapshot.filePath());
      if (scan == null) {
        throw new IOException(
            "Missing dynamic-root scan for retained artifact " + snapshot.coordinate());
      }
      retainedDynamicRoots.addAll(scan.roots());
    }

    final Set<Path> distinctOutputs = new HashSet<>();
    final List<CandidateWork> work = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot candidate :
        retained.stream().sorted(artifactSnapshotOrder()).toList()) {
      final Set<String> candidateClasses =
          classesByArtifact.entrySet().stream()
              .filter(entry -> entry.getKey().filePath().equals(candidate.filePath()))
              .map(Map.Entry::getValue)
              .findFirst()
              .orElseThrow(
                  () -> new IOException("Missing indexed classes for " + candidate.coordinate()));
      if (candidateClasses.isEmpty()) {
        continue;
      }
      final Set<String> roots = new TreeSet<>();
      addPresentRoots(roots, allRoots, candidateClasses);
      addPresentRoots(roots, retainedDynamicRoots, candidateClasses);
      final Path output = outputPath(project, candidate.coordinate());
      if (!distinctOutputs.add(output)) {
        throw new IOException(
            "Distinct Maven artifacts map to the same trimmed output path: " + output);
      }
      work.add(new CandidateWork(candidate, candidateClasses, roots, output));
    }

    final Map<String, List<CandidateWork>> ownersByClass = new java.util.HashMap<>();
    final Map<String, Path> ownerByClass = new java.util.HashMap<>();
    for (final CandidateWork candidate : work) {
      for (final String className : candidate.classes()) {
        final Path previous = ownerByClass.putIfAbsent(className, candidate.snapshot().filePath());
        if (previous != null && !previous.equals(candidate.snapshot().filePath())) {
          throw new IOException(
              "Duplicate class across retained dependency JARs makes library order ambiguous: "
                  + className);
        }
        ownersByClass.computeIfAbsent(className, ignored -> new ArrayList<>()).add(candidate);
      }
    }
    return new CandidatePlan(retainedInputPaths, work, ownersByClass, ownerByClass);
  }

  private static CandidatePlan effectiveCandidatePlan(
      final MavenProject project,
      final List<MavenElisionService.ArtifactSnapshot> retainedLibraries,
      final List<MavenElisionService.ArtifactSnapshot> retained,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact,
      final EffectiveOutputPlan effectiveOutput)
      throws IOException {
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> rootsBySnapshot =
        validateDiscoveredRoots(
            effectiveOutput.roots(),
            fullJarInventory(retainedLibraries),
            classesByPath(classesByArtifact));
    final List<Path> retainedInputPaths =
        retainedLibraries.stream().map(MavenElisionService.ArtifactSnapshot::filePath).toList();
    final Set<Path> distinctOutputs = new HashSet<>();
    final List<CandidateWork> work = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot candidate :
        retained.stream().sorted(artifactSnapshotOrder()).toList()) {
      if (effectiveOutput.unchangedCoordinates().contains(candidate.coordinate())) {
        continue;
      }
      final boolean multiRelease =
          effectiveOutput.analysis().upperTierClasses().containsKey(candidate.coordinate());
      final Set<String> candidateClasses;
      final int logicalClassCount;
      if (multiRelease) {
        final Path targetProjection =
            MultiReleaseLibraryProjection.create(
                candidate.filePath(),
                candidate.coordinate(),
                analysisLibraryDirectory(project),
                effectiveOutput.analysis().compilerRelease());
        candidateClasses = classNames(targetProjection);
        final MultiReleaseArchivePlan initialPlan =
            MultiReleaseArchivePlan.create(
                candidate.filePath(),
                effectiveOutput.analysis().compilerRelease(),
                Set.of(),
                Set.of());
        logicalClassCount = initialPlan.pluginView().logicalClassCount();
      } else {
        candidateClasses = classesFor(candidate, classesByArtifact);
        logicalClassCount = candidateClasses.size();
      }
      if (candidateClasses.isEmpty() && !multiRelease) {
        continue;
      }
      final Set<String> discovered = rootsBySnapshot.get(candidate);
      if (discovered == null) {
        throw new IOException("Effective analysis has no roots for " + candidate.coordinate());
      }
      final Set<String> roots = new TreeSet<>(discovered);
      roots.retainAll(candidateClasses);
      final Path output = outputPath(project, candidate.coordinate());
      if (!distinctOutputs.add(output)) {
        throw new IOException("Distinct effective candidates share output path: " + output);
      }
      final CandidateWork candidateWork =
          new CandidateWork(
              candidate, candidateClasses, roots, output, multiRelease, logicalClassCount);
      candidateWork.upperTierClasses(
          effectiveOutput
              .analysis()
              .upperTierClasses()
              .getOrDefault(candidate.coordinate(), Set.of()));
      work.add(candidateWork);
    }
    return new CandidatePlan(retainedInputPaths, work, Map.of(), Map.of());
  }

  private static void verifyEffectiveInputs(
      final EffectiveOutputPlan plan, final FingerprintSnapshot fingerprint) throws IOException {
    MavenElisionService.verifyPreparedInventory(plan.prepared());
    for (final Map.Entry<Path, ArtifactDigests> entry : fingerprint.inputDigests().entrySet()) {
      if (!entry.getValue().sha256().equals(ArtifactDigests.read(entry.getKey()).sha256())) {
        throw new IOException(
            "Artifact input changed during effective output trim: " + entry.getKey());
      }
    }
    final MavenElisionService.PreparedAnalysis prepared = plan.prepared();
    if (prepared.bytecodeScan().isPresent()
        && !plan.productionOutputFingerprint()
            .equals(
                ProductionOutputFingerprint.fingerprint(
                    prepared.bytecodeScan().orElseThrow().scope()))) {
      throw new IOException("Production output changed during effective output trim");
    }
  }

  static Path generationPath(final MavenProject project, final String fingerprint) {
    return buildDirectory(project)
        .resolve(ELIDED_ARTIFACTS)
        .resolve(".generations")
        .resolve(fingerprint);
  }

  private static Path cacheManifestPath(final MavenProject project) {
    return buildDirectory(project).resolve(ELIDED_ARTIFACTS).resolve(".trim-analysis-cache.json");
  }

  private static Path buildDirectory(final MavenProject project) {
    final Path configured =
        project.getBuild() == null || project.getBuild().getDirectory() == null
            ? Path.of(DEFAULT_BUILD_DIRECTORY)
            : Path.of(project.getBuild().getDirectory());
    return configured.toAbsolutePath().normalize();
  }

  private static Map<Path, Set<String>> classesByPath(
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact) {
    final Map<Path, Set<String>> result = new java.util.LinkedHashMap<>();
    classesByArtifact.forEach(
        (artifact, classes) ->
            result.put(artifact.filePath().toAbsolutePath().normalize(), classes));
    return result;
  }

  private static Set<String> classesFor(
      final MavenElisionService.ArtifactSnapshot snapshot,
      final Map<io.github.spockz.elider.model.ArtifactFileRef, Set<String>> classesByArtifact)
      throws IOException {
    return classesByArtifact.entrySet().stream()
        .filter(
            entry ->
                entry
                    .getKey()
                    .filePath()
                    .toAbsolutePath()
                    .normalize()
                    .equals(snapshot.filePath().toAbsolutePath().normalize()))
        .map(Map.Entry::getValue)
        .findFirst()
        .orElseThrow(() -> new IOException("Missing indexed classes for " + snapshot.coordinate()));
  }

  private static void assignEffectiveAnalyses(
      final CandidatePlan plan, final InMemoryAnalysis analysis) throws IOException {
    if (plan.work().size() != analysis.candidateAnalyses().size()) {
      throw new IOException("Effective analysis candidate inventory changed before output trim");
    }
    for (final CandidateWork candidate : plan.work()) {
      final DependencyJarTrimmer.TrimAnalysis candidateAnalysis =
          analysis.candidateAnalyses().get(candidate.snapshot().coordinate());
      if (candidateAnalysis == null
          || !candidateAnalysis.roots().stream()
              .map(name -> name.replace('/', '.'))
              .collect(java.util.stream.Collectors.toSet())
              .equals(candidate.targetRoots())) {
        throw new IOException(
            "Output candidate roots do not match effective analysis: "
                + candidate.snapshot().coordinate());
      }
      candidate.analysis(candidateAnalysis);
    }
  }

  private static List<MavenElisionService.ArtifactSnapshot> fullJarInventory(
      final List<MavenElisionService.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
        .sorted(artifactSnapshotOrder())
        .toList();
  }

  static Comparator<MavenElisionService.ArtifactSnapshot> artifactSnapshotOrder() {
    return Comparator.comparing(MavenElisionService.ArtifactSnapshot::coordinate)
        .thenComparing(snapshot -> snapshot.filePath().toAbsolutePath().normalize());
  }

  private static String effectiveCacheContext(
      final TrimRequest request, final EffectiveOutputPlan output) throws IOException {
    final List<ArtifactCacheIdentity> inventory = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot :
        fullJarInventory(request.candidates())) {
      inventory.add(artifactCacheIdentity(snapshot));
    }
    final List<ArtifactRootsIdentity> artifactRoots =
        output.roots().entrySet().stream()
            .sorted(
                Comparator.comparing(
                        (Map.Entry<ArtifactRootKey, Set<String>> entry) ->
                            entry.getKey().coordinate())
                    .thenComparing(entry -> entry.getKey().path()))
            .map(
                entry ->
                    new ArtifactRootsIdentity(
                        entry.getKey().coordinate(),
                        entry.getKey().path().toString(),
                        entry.getKey().sha256(),
                        entry.getValue().stream().sorted().toList()))
            .toList();
    final EffectiveCacheIdentity identity =
        new EffectiveCacheIdentity(
            2,
            output.inventoryFingerprint(),
            output.directInventoryFingerprint(),
            output.operationFingerprint(),
            output.productionOutputFingerprint(),
            inventory,
            request.retainedCoordinates().stream().sorted().toList(),
            output.unchangedCoordinates().stream().sorted().toList(),
            artifactRoots,
            output.analysis().compilerRelease(),
            output.analysis().runtimeRelease(),
            output.analysis().javaHome().toString(),
            output.analysis().platformIdentities(),
            output.analysis().analyzedTiers(),
            output.bytecodeReferences().stream().sorted().toList(),
            output.explicitRoots().stream().sorted().toList(),
            output.explicitPassThroughCoordinates().stream().sorted().toList(),
            output.sourceRootsComplete(),
            output.productionClassesComplete(),
            request.mrjarStrategy(),
            output.failOnUnsupportedModuleInfo());
    try {
      return hash(JSON.writeValueAsBytes(identity));
    } catch (final com.fasterxml.jackson.core.JsonProcessingException exception) {
      throw new IOException("Could not serialize effective trim cache identity", exception);
    }
  }

  private static ArtifactCacheIdentity artifactCacheIdentity(
      final MavenElisionService.ArtifactSnapshot snapshot) throws IOException {
    final ArtifactCoordinate coordinate = snapshot.coordinate();
    final Path path = snapshot.filePath().toAbsolutePath().normalize();
    return new ArtifactCacheIdentity(
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.version(),
        coordinate.type(),
        coordinate.classifier(),
        coordinate.scope(),
        path.toString(),
        ArtifactDigests.read(path).sha256());
  }

  private static void addPresentRoots(
      final Set<String> roots, final Set<String> candidates, final Set<String> candidateClasses) {
    for (final String root : candidates) {
      final String normalized = root.replace('/', '.');
      if (candidateClasses.contains(normalized)) {
        roots.add(normalized);
      }
    }
  }

  static Set<String> classNames(final Path archivePath) throws IOException {
    final Set<String> classNames = new TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final var entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        if (name.endsWith(CLASS_SUFFIX)
            && !"module-info.class".equals(name)
            && !name.endsWith("/module-info.class")) {
          classNames.add(
              name.substring(0, name.length() - CLASS_SUFFIX.length()).replace('/', '.'));
        }
      }
    }
    return Set.copyOf(classNames);
  }

  static Set<String> logicalClassNames(final Path archivePath) throws IOException {
    return MultiReleaseClassInventory.logicalClassNames(archivePath);
  }

  static Path outputPath(final MavenProject project, final ArtifactCoordinate coordinate) {
    final String basename =
        safeFilePart(coordinate.groupId())
            + "-"
            + safeFilePart(coordinate.artifactId())
            + "-"
            + safeFilePart(coordinate.version())
            + (coordinate.classifier().isBlank() ? "" : "-" + safeFilePart(coordinate.classifier()))
            + "-trimmed.jar";
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of(DEFAULT_BUILD_DIRECTORY, ELIDED_ARTIFACTS, basename).toAbsolutePath().normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, basename)
            .toAbsolutePath()
            .normalize();
  }

  private static final class CandidateWork {
    private final MavenElisionService.ArtifactSnapshot snapshot;
    private final Set<String> classes;
    private final Set<String> roots;
    private final boolean multiRelease;
    private final int logicalClassCount;
    private Set<String> upperTierClasses = Set.of();
    private Path output;
    private DependencyJarTrimmer.TrimAnalysis analysis;

    private CandidateWork(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> classes,
        final Set<String> roots,
        final Path output) {
      this(snapshot, classes, roots, output, false, classes.size());
    }

    private CandidateWork(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> classes,
        final Set<String> roots,
        final Path output,
        final boolean multiRelease,
        final int logicalClassCount) {
      this.snapshot = snapshot;
      this.classes = Set.copyOf(classes);
      this.roots = new TreeSet<>(multiRelease || !roots.isEmpty() ? roots : classes);
      this.output = output;
      this.multiRelease = multiRelease;
      this.logicalClassCount = logicalClassCount;
    }

    private MavenElisionService.ArtifactSnapshot snapshot() {
      return snapshot;
    }

    private Set<String> classes() {
      return classes;
    }

    private Set<String> roots() {
      return roots;
    }

    private Set<String> targetRoots() {
      final Set<String> result = new TreeSet<>(roots);
      result.retainAll(classes);
      return Set.copyOf(result);
    }

    private boolean isMultiRelease() {
      return multiRelease;
    }

    private int logicalClassCount() {
      return logicalClassCount;
    }

    private Set<String> upperTierClasses() {
      return upperTierClasses;
    }

    private void upperTierClasses(final Set<String> value) {
      upperTierClasses = Set.copyOf(value);
    }

    private boolean requiresOutput() {
      return multiRelease
          || analysis == null
          || analysis.retainedClasses().size() < analysis.totalClasses();
    }

    private Path output() {
      return output;
    }

    private void output(final Path value) {
      output = value;
    }

    private DependencyJarTrimmer.TrimAnalysis analysis() {
      return analysis;
    }

    private void analysis(final DependencyJarTrimmer.TrimAnalysis value) {
      analysis = value;
    }
  }

  private record SkippedProgram(Path path, Set<String> classNames) {
    private SkippedProgram {
      classNames = Set.copyOf(classNames);
    }
  }

  private record PendingOutput(CandidateWork candidate, ArchiveSanitizer.PreparedOutput prepared) {}

  private record ServiceProviderInventory(Set<String> ownedClasses, Set<String> retainedClasses) {
    private ServiceProviderInventory {
      ownedClasses = Set.copyOf(ownedClasses);
      retainedClasses = Set.copyOf(retainedClasses);
    }
  }

  @FunctionalInterface
  private interface CleanupAction {
    void run() throws IOException;
  }

  // Deferred cleanup must not remove files while a cancelled worker can still write them.
  @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
  private static final class PreparedOutputCleanup implements AutoCloseable {
    private final ArchiveSanitizer sanitizer;
    private final Queue<PendingOutput> pendingOutputs = new ConcurrentLinkedQueue<>();
    private final List<CleanupAction> cleanupActions = new ArrayList<>();
    private ExecutorService deferredExecutor;

    private PreparedOutputCleanup(final ArchiveSanitizer sanitizer) {
      this.sanitizer = sanitizer;
    }

    private PendingOutput track(final PendingOutput pending) {
      pendingOutputs.add(pending);
      return pending;
    }

    private void addCleanupAction(final CleanupAction cleanupAction) {
      cleanupActions.add(cleanupAction);
    }

    private void deferUntil(final ExecutorService executor) {
      deferredExecutor = executor;
    }

    @Override
    @SuppressWarnings("PMD.CloseResource")
    public void close() throws IOException {
      if (deferredExecutor != null && !deferredExecutor.isTerminated()) {
        final ExecutorService executor = deferredExecutor;
        Thread.ofVirtual()
            .name("dependency-elider-staging-cleanup")
            .start(
                () -> {
                  awaitTerminationUninterruptibly(executor);
                  executor.close();
                  try {
                    cleanupResources();
                  } catch (final IOException exception) {
                    System.getLogger(MavenDependencyTrimmer.class.getName())
                        .log(
                            System.Logger.Level.ERROR,
                            "Could not clean deferred trim staging",
                            exception);
                  }
                });
        return;
      }
      cleanupResources();
    }

    private void cleanupResources() throws IOException {
      IOException cleanupFailure = null;
      for (final PendingOutput pending : pendingOutputs) {
        try {
          sanitizer.discard(pending.prepared());
        } catch (final IOException exception) {
          cleanupFailure = appendFailure(cleanupFailure, exception);
        }
      }
      for (final CleanupAction cleanupAction : cleanupActions) {
        try {
          cleanupAction.run();
        } catch (final IOException exception) {
          cleanupFailure = appendFailure(cleanupFailure, exception);
        }
      }
      if (cleanupFailure != null) {
        throw cleanupFailure;
      }
    }
  }

  @FunctionalInterface
  interface PreparedOutputPublisher {
    ArtifactTrimRecord publish(ArchiveSanitizer.PreparedOutput prepared) throws IOException;
  }

  static List<ArtifactTrimRecord> publishOutputs(
      final List<ArchiveSanitizer.PreparedOutput> preparedOutputs,
      final PreparedOutputPublisher publisher)
      throws IOException {
    final List<ArtifactTrimRecord> records = new ArrayList<>(preparedOutputs.size());
    for (final ArchiveSanitizer.PreparedOutput prepared : preparedOutputs) {
      records.add(publisher.publish(prepared));
    }
    return List.copyOf(records);
  }

  @FunctionalInterface
  interface TrimmerWorkItem<T, R> {
    R execute(T item) throws IOException;
  }

  private static int trimParallelism(final int workSize, final int maxWorkers) {
    if (workSize <= 1) {
      return 1;
    }
    final int available = Runtime.getRuntime().availableProcessors();
    return Math.max(1, Math.min(Math.min(available, maxWorkers), workSize));
  }

  static <T, R> List<R> mapParallel(
      final List<T> items, final int maxWorkers, final TrimmerWorkItem<T, R> task)
      throws IOException {
    return mapParallel(items, maxWorkers, task, null);
  }

  // Closing a timed-out executor here would undo the bounded cancellation wait.
  @SuppressWarnings({
    "PMD.AvoidCatchingGenericException",
    "PMD.CloseResource",
    DO_NOT_USE_THREADS_SUPPRESSION,
    "PMD.PreserveStackTrace"
  })
  private static <T, R> List<R> mapParallel(
      final List<T> items,
      final int maxWorkers,
      final TrimmerWorkItem<T, R> task,
      final PreparedOutputCleanup deferredCleanup)
      throws IOException {
    if (items.isEmpty()) {
      return List.of();
    }
    final int parallelism = trimParallelism(items.size(), maxWorkers);
    if (parallelism <= 1) {
      final List<R> results = new ArrayList<>(items.size());
      for (final T item : items) {
        try {
          results.add(task.execute(item));
        } catch (final IOException | RuntimeException exception) {
          throw parallelTaskFailure(exception);
        }
      }
      return List.copyOf(results);
    }
    final ExecutorService executor =
        Executors.newFixedThreadPool(
            parallelism,
            Thread.ofPlatform().daemon().name("dependency-elider-worker-", 0).factory());
    try {
      final CompletionService<IndexedResult<R>> completions =
          new ExecutorCompletionService<>(executor);
      final List<Future<IndexedResult<R>>> active = new ArrayList<>(parallelism);
      final List<R> results = new ArrayList<>(java.util.Collections.nCopies(items.size(), null));
      int nextIndex = 0;
      int completed = 0;
      try {
        while (completed < items.size()) {
          while (nextIndex < items.size() && active.size() < parallelism) {
            final int index = nextIndex;
            nextIndex++;
            active.add(
                completions.submit(
                    () -> new IndexedResult<>(index, task.execute(items.get(index)))));
          }
          final Future<IndexedResult<R>> finished = completions.take();
          active.remove(finished);
          final IndexedResult<R> result = finished.get();
          results.set(result.index(), result.value());
          completed++;
        }
        executor.shutdown();
        return List.copyOf(results);
      } catch (final InterruptedException e) {
        final boolean terminated = cancelParallelWork(executor, active, deferredCleanup);
        Thread.currentThread().interrupt();
        final IOException failure =
            new IOException("Interrupted while executing parallel trimming tasks", e);
        if (!terminated) {
          failure.addSuppressed(cancellationTimeoutFailure());
        }
        throw failure;
      } catch (final ExecutionException e) {
        final boolean terminated = cancelParallelWork(executor, active, deferredCleanup);
        final Throwable cause = e.getCause();
        if (cause instanceof Error error) {
          if (!terminated) {
            error.addSuppressed(cancellationTimeoutFailure());
          }
          throw error;
        }
        final IOException failure = parallelTaskFailure(cause);
        if (!terminated) {
          failure.addSuppressed(cancellationTimeoutFailure());
        }
        throw failure;
      } catch (final RuntimeException | Error e) {
        if (!cancelParallelWork(executor, active, deferredCleanup)) {
          e.addSuppressed(cancellationTimeoutFailure());
        }
        throw e;
      }
    } finally {
      if (!executor.isShutdown()) {
        executor.shutdownNow();
      }
    }
  }

  @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
  private static boolean cancelParallelWork(
      final ExecutorService executor,
      final List<? extends Future<?>> active,
      final PreparedOutputCleanup deferredCleanup) {
    active.forEach(future -> future.cancel(true));
    executor.shutdownNow();
    boolean interrupted = false;
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(CANCELLATION_GRACE_SECONDS);
    while (!executor.isTerminated()) {
      final long remainingNanos = deadline - System.nanoTime();
      if (remainingNanos <= 0) {
        break;
      }
      try {
        executor.awaitTermination(remainingNanos, TimeUnit.NANOSECONDS);
      } catch (final InterruptedException exception) {
        interrupted = true;
      }
    }
    final boolean terminated = executor.isTerminated();
    if (!terminated && deferredCleanup != null) {
      deferredCleanup.deferUntil(executor);
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
    return terminated;
  }

  @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
  private static void awaitTerminationUninterruptibly(final ExecutorService executor) {
    boolean interrupted = false;
    while (!executor.isTerminated()) {
      try {
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
      } catch (final InterruptedException exception) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private static IOException appendFailure(final IOException previous, final IOException next) {
    if (previous == null) {
      return next;
    }
    previous.addSuppressed(next);
    return previous;
  }

  private static IOException cancellationTimeoutFailure() {
    return new IOException(
        "Parallel trimming workers did not stop within "
            + CANCELLATION_GRACE_SECONDS
            + " seconds; running tasks were detached");
  }

  private static IOException parallelTaskFailure(final Throwable cause) {
    final String detail = cause.getMessage();
    return new IOException(
        detail == null
            ? "Parallel trimming task failed"
            : "Parallel trimming task failed: " + detail,
        cause);
  }

  private static FingerprintSnapshot fingerprint(
      final List<CandidateWork> candidates,
      final List<Path> allRetainedInputs,
      final Set<String> skippedArtifactIdentities,
      final FingerprintOptions options)
      throws IOException {
    final List<String> candidateIdentities = new ArrayList<>();
    final Set<String> roots = new TreeSet<>();
    for (final CandidateWork candidate : candidates) {
      candidateIdentities.add(
          candidate.snapshot().coordinate()
              + ":"
              + candidate.snapshot().filePath().toAbsolutePath().normalize());
      roots.addAll(candidate.roots());
    }
    candidateIdentities.addAll(
        skippedArtifactIdentities.stream()
            .sorted()
            .map(identity -> "trim-skip:" + identity)
            .toList());
    if (options.outputContext() != null) {
      candidateIdentities.add("effective-output-context:" + options.outputContext());
    }
    candidateIdentities.add("runtime-release:" + options.runtimeRelease());
    final Set<Integer> tiers = new TreeSet<>(options.analyzedTiers());
    tiers.add(options.release());
    tiers.add(options.runtimeRelease());
    final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots = new ArrayList<>();
    for (final int tier : tiers) {
      platformSnapshots.add(options.platformContext().snapshot(tier));
    }
    platformSnapshots.sort(
        Comparator.comparingInt(JdkPlatformContext.PlatformSnapshot::effectiveRelease));
    final Map<Path, ArtifactDigests> inputDigests = inputDigests(allRetainedInputs);
    final String value =
        fingerprintForPlatformSnapshots(
            candidateIdentities,
            allRetainedInputs,
            roots,
            platformSnapshots,
            options.release(),
            options.schemaVersion(),
            options.engineVersion(),
            inputDigests);
    return new FingerprintSnapshot(value, inputDigests, List.copyOf(platformSnapshots));
  }

  private static JdkPlatformContext.PlatformSnapshot platformSnapshot(
      final List<JdkPlatformContext.PlatformSnapshot> snapshots, final int release) {
    return snapshots.stream()
        .filter(snapshot -> snapshot.effectiveRelease() == release)
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalStateException("No captured platform snapshot for release " + release));
  }

  private static PlatformPools readPlatformPools(
      final List<JdkPlatformContext.PlatformSnapshot> snapshots,
      final int compilerRelease,
      final int runtimeRelease)
      throws IOException {
    final JdkApiClassPoolReader reader = new JdkApiClassPoolReader();
    final ClassPool compiler = reader.readFrozen(platformSnapshot(snapshots, compilerRelease));
    final ClassPool runtime =
        runtimeRelease == compilerRelease
            ? compiler
            : reader.readFrozen(platformSnapshot(snapshots, runtimeRelease));
    return new PlatformPools(compiler, runtime);
  }

  static String artifactIdentity(final ArtifactCoordinate coordinate) {
    return coordinate.groupId()
        + ":"
        + coordinate.artifactId()
        + ":"
        + coordinate.version()
        + ":"
        + coordinate.type()
        + ":"
        + coordinate.classifier();
  }

  private static Set<String> identities(
      final List<MavenElisionService.ArtifactSnapshot> snapshots) {
    return snapshots.stream()
        .map(snapshot -> artifactIdentity(snapshot.coordinate()))
        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
  }

  private static List<MavenElisionService.ArtifactSnapshot> parsePassThroughArtifacts(
      final List<String> requested,
      final List<MavenElisionService.ArtifactSnapshot> retainedLibraries)
      throws IOException {
    final Set<String> requestedIdentities = new LinkedHashSet<>();
    for (final String raw : requested) {
      if (raw == null || raw.isBlank()) {
        throw new IOException("elide.trimSkipArtifacts must not contain blank coordinates");
      }
      final String[] parts = raw.trim().split(":", -1);
      if (parts.length < 3
          || parts.length > 5
          || parts[0].isBlank()
          || parts[1].isBlank()
          || parts[2].isBlank()) {
        throw new IOException(
            "Invalid elide.trimSkipArtifacts coordinate; expected "
                + "group:artifact:version[:type[:classifier]]: "
                + raw);
      }
      final String groupId = parts[0];
      final String artifactId = parts[1];
      final String version = parts[2];
      final String type = parts.length > 3 && !parts[3].isBlank() ? parts[3] : JAR_TYPE;
      final String classifier = parts.length > 4 ? parts[4] : "";
      final List<MavenElisionService.ArtifactSnapshot> matches =
          retainedLibraries.stream()
              .filter(
                  snapshot -> {
                    final ArtifactCoordinate coordinate = snapshot.coordinate();
                    return coordinate.groupId().equals(groupId)
                        && coordinate.artifactId().equals(artifactId)
                        && coordinate.version().equals(version)
                        && coordinate.type().equals(type)
                        && coordinate.classifier().equals(classifier);
                  })
              .toList();
      if (matches.isEmpty()) {
        throw new IOException(
            "elide.trimSkipArtifacts coordinate is not a retained compile/runtime JAR: " + raw);
      }
      matches.stream()
          .map(snapshot -> artifactIdentity(snapshot.coordinate()))
          .forEach(requestedIdentities::add);
    }
    return retainedLibraries.stream()
        .filter(snapshot -> requestedIdentities.contains(artifactIdentity(snapshot.coordinate())))
        .toList();
  }

  static String fingerprintForInputs(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<Path> platformInputs,
      final int release,
      final int schemaVersion,
      final String engineVersion)
      throws IOException {
    return fingerprintForInputs(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformInputs,
        release,
        schemaVersion,
        engineVersion,
        inputDigests(orderedLibraries));
  }

  private static String fingerprintForInputs(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<Path> platformInputs,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final List<String> platformIdentities = new ArrayList<>(platformInputs.size());
    for (final Path platformInput : platformInputs) {
      platformIdentities.add(
          platformInput.toAbsolutePath().normalize().getFileName() + ":" + sha256(platformInput));
    }
    return fingerprintForPlatformIdentities(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformIdentities,
        release,
        schemaVersion,
        engineVersion,
        inputDigests);
  }

  private static String fingerprintForPlatformSnapshots(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final List<String> platformIdentities =
        platformSnapshots.stream().map(JdkPlatformContext.PlatformSnapshot::identity).toList();
    return fingerprintForPlatformIdentities(
        candidateIdentities,
        orderedLibraries,
        roots,
        platformIdentities,
        release,
        schemaVersion,
        engineVersion,
        inputDigests);
  }

  private static String fingerprintForPlatformIdentities(
      final List<String> candidateIdentities,
      final List<Path> orderedLibraries,
      final Set<String> roots,
      final List<String> platformIdentities,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final Map<Path, ArtifactDigests> inputDigests)
      throws IOException {
    final StringBuilder input =
        new StringBuilder("release=")
            .append(release)
            .append("\nschema=")
            .append(schemaVersion)
            .append("\nengine=")
            .append(engineVersion)
            .append('\n');
    for (final String candidateIdentity : candidateIdentities) {
      input.append("candidate=").append(candidateIdentity).append('\n');
    }
    for (final String root : new TreeSet<>(roots)) {
      input.append("root=").append(root).append('\n');
    }
    for (int index = 0; index < orderedLibraries.size(); index++) {
      final Path library = orderedLibraries.get(index);
      input
          .append("library[")
          .append(index)
          .append("]=")
          .append(library.toAbsolutePath().normalize())
          .append(':')
          .append(requiredInputDigest(inputDigests, library).sha256())
          .append('\n');
    }
    for (int index = 0; index < platformIdentities.size(); index++) {
      input
          .append("platform[")
          .append(index)
          .append("]=")
          .append(platformIdentities.get(index))
          .append('\n');
    }
    return hash(input.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
  }

  private static Map<Path, ArtifactDigests> inputDigests(final List<Path> inputPaths)
      throws IOException {
    final Map<Path, ArtifactDigests> digests = new java.util.LinkedHashMap<>();
    for (final Path inputPath : inputPaths) {
      final Path normalizedPath = inputPath.toAbsolutePath().normalize();
      if (!digests.containsKey(normalizedPath)) {
        digests.put(normalizedPath, ArtifactDigests.read(normalizedPath));
      }
    }
    return Map.copyOf(digests);
  }

  private static ArtifactDigests requiredInputDigest(
      final Map<Path, ArtifactDigests> inputDigests, final Path inputPath) {
    final Path normalizedPath = inputPath.toAbsolutePath().normalize();
    final ArtifactDigests digest = inputDigests.get(normalizedPath);
    if (digest == null) {
      throw new IllegalStateException(
          "Missing input digest for retained archive: " + normalizedPath);
    }
    return digest;
  }

  private static CacheEntry cacheEntry(
      final CandidateWork candidate,
      final ArtifactTrimRecord record,
      final Map<Path, ArtifactDigests> inputDigests) {
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    final ArtifactDigests originalDigests =
        requiredInputDigest(inputDigests, candidate.snapshot().filePath());
    final CacheOutputMetadata output =
        cacheOutputMetadata(candidate, record, analysis, originalDigests);
    return new CacheEntry(
        candidate.snapshot().filePath().toAbsolutePath().normalize().toString(),
        originalDigests.sha256(),
        output.originalSha1(),
        output.trimmedPath(),
        output.trimmedSha256(),
        output.trimmedSha1(),
        output.totalClasses(),
        output.retainedClasses(),
        output.prunedClassBytes(),
        candidate.targetRoots(),
        analysis.retainedClasses(),
        analysis.reachableLibraryClasses(),
        output.originalPhysicalEntries(),
        output.trimmedPhysicalEntries(),
        output.mrjarStatus());
  }

  private static CacheOutputMetadata cacheOutputMetadata(
      final CandidateWork candidate,
      final ArtifactTrimRecord record,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests) {
    if (record == null) {
      return new CacheOutputMetadata(
          null,
          null,
          null,
          null,
          candidate.logicalClassCount(),
          analysis.retainedClasses().size(),
          0L,
          null,
          null,
          "not_multi_release");
    }
    return new CacheOutputMetadata(
        originalDigests.sha1(),
        record.trimmedPath().toString(),
        record.trimmedSha256(),
        record.trimmedSha1(),
        record.totalClasses(),
        record.retainedClasses(),
        record.prunedClassBytes(),
        record.originalPhysicalEntries().orElseThrow(),
        record.trimmedPhysicalEntries().orElseThrow(),
        record.mrjarStatus());
  }

  private static TrimResult loadCache(
      final Path manifestPath,
      final String fingerprint,
      final Map<Path, ArtifactDigests> inputDigests,
      final List<CandidateWork> candidates,
      final List<ArtifactCoordinate> multiReleasePassthroughArtifacts,
      final List<ArtifactCoordinate> moduleInfoPassthroughArtifacts,
      final List<ArtifactCoordinate> configuredPassThroughArtifacts,
      final long started)
      throws IOException {
    if (!Files.isRegularFile(manifestPath)) {
      return null;
    }
    final CacheManifest manifest;
    try {
      manifest = JSON.readValue(manifestPath.toFile(), CacheManifest.class);
    } catch (final IOException exception) {
      return null;
    }
    if (manifest == null
        || manifest.schemaVersion() != CACHE_SCHEMA_VERSION
        || !CACHE_FORMAT_ID.equals(manifest.formatId())
        || manifest.entries() == null
        || !fingerprint.equals(manifest.fingerprint())
        || manifest.entries().size() != candidates.size()) {
      return null;
    }
    final List<ArtifactTrimRecord> records = new ArrayList<>();
    for (int index = 0; index < candidates.size(); index++) {
      final CandidateWork candidate = candidates.get(index);
      final CacheEntry entry = manifest.entries().get(index);
      final Path original = candidate.snapshot().filePath().toAbsolutePath().normalize();
      final ArtifactDigests originalDigests = requiredInputDigest(inputDigests, original);
      if (!validCacheEntry(entry, candidate)) {
        return null;
      }
      if (!original.toString().equals(entry.originalPath())
          || !originalDigests.sha256().equals(entry.originalSha256())) {
        return null;
      }
      if (entry.originalPhysicalEntries() != null
          && entry.originalPhysicalEntries() != physicalEntryCount(original)) {
        return null;
      }
      if (entry.trimmedPath() != null && !originalDigests.sha1().equals(entry.originalSha1())) {
        return null;
      }
      if (entry.trimmedPath() == null) {
        continue;
      }
      final Path output = candidate.output().toAbsolutePath().normalize();
      if (!output.toString().equals(entry.trimmedPath()) || !Files.isRegularFile(output)) {
        return null;
      }
      final ArtifactDigests outputDigests = ArtifactDigests.read(output);
      if (!entry.trimmedSha256().equals(outputDigests.sha256())
          || !entry.trimmedSha1().equals(outputDigests.sha1())
          || entry.trimmedPhysicalEntries() != physicalEntryCount(output)) {
        return null;
      }
      records.add(
          new ArtifactTrimRecord(
              candidate.snapshot().coordinate(),
              original.toRealPath(),
              entry.originalSha256(),
              entry.originalSha1(),
              output.toRealPath(),
              entry.trimmedSha256(),
              entry.trimmedSha1(),
              entry.totalClasses(),
              entry.retainedClasses(),
              entry.prunedClassBytes(),
              entry.originalPhysicalEntries(),
              entry.trimmedPhysicalEntries(),
              entry.mrjarStatus()));
    }
    return new TrimResult(
        records,
        multiReleasePassthroughArtifacts,
        moduleInfoPassthroughArtifacts,
        configuredPassThroughArtifacts,
        records.size(),
        System.nanoTime() - started,
        0);
  }

  private static boolean validCacheEntry(final CacheEntry entry, final CandidateWork candidate) {
    if (entry == null) {
      return false;
    }
    return validCacheMetadata(entry, candidate)
        && validRetainedClassEvidence(entry, candidate)
        && validCacheOutput(entry, candidate);
  }

  private static boolean validCacheMetadata(final CacheEntry entry, final CandidateWork candidate) {
    return validCacheCollections(entry)
        && validCacheCounts(entry, candidate)
        && validCacheStatus(entry, candidate)
        && candidate.targetRoots().containsAll(entry.roots());
  }

  private static boolean validCacheCollections(final CacheEntry entry) {
    return validDigest(entry.originalSha256(), 64)
        && entry.roots() != null
        && !entry.roots().contains(null)
        && entry.retainedClassNames() != null
        && !entry.retainedClassNames().contains(null)
        && entry.prunedClassBytes() != null
        && entry.prunedClassBytes() >= 0
        && entry.reachableLibraryClasses() != null
        && !entry.reachableLibraryClasses().contains(null);
  }

  private static boolean validCacheCounts(final CacheEntry entry, final CandidateWork candidate) {
    return entry.totalClasses() == candidate.logicalClassCount()
        && entry.retainedClasses() >= 0
        && entry.retainedClasses() <= entry.totalClasses()
        && (candidate.isMultiRelease()
            || entry.retainedClassNames().size() == entry.retainedClasses());
  }

  private static boolean validCacheStatus(final CacheEntry entry, final CandidateWork candidate) {
    return candidate.isMultiRelease()
        ? "elevated_and_trimmed".equals(entry.mrjarStatus())
        : "not_multi_release".equals(entry.mrjarStatus());
  }

  private static boolean validRetainedClassEvidence(
      final CacheEntry entry, final CandidateWork candidate) {
    return validMultiReleaseRetainedCount(entry, candidate)
        && matchesCurrentAnalysis(entry, candidate)
        && retainedClassNamesBelongToCandidate(entry, candidate);
  }

  private static boolean validMultiReleaseRetainedCount(
      final CacheEntry entry, final CandidateWork candidate) {
    if (!candidate.isMultiRelease()) {
      return true;
    }
    final Set<String> logicalRetained = normalizedNames(entry.retainedClassNames());
    logicalRetained.addAll(candidate.upperTierClasses());
    return logicalRetained.size() == entry.retainedClasses();
  }

  private static boolean matchesCurrentAnalysis(
      final CacheEntry entry, final CandidateWork candidate) {
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    return analysis == null
        || (candidate.targetRoots().equals(entry.roots())
            && candidate.targetRoots().equals(normalizedNames(analysis.roots()))
            && entry.retainedClassNames().equals(analysis.retainedClasses())
            && entry.reachableLibraryClasses().equals(analysis.reachableLibraryClasses()));
  }

  private static boolean retainedClassNamesBelongToCandidate(
      final CacheEntry entry, final CandidateWork candidate) {
    for (final String retainedClass : entry.retainedClassNames()) {
      if (!candidate.classes().contains(retainedClass.replace('/', '.'))) {
        return false;
      }
    }
    return true;
  }

  private static boolean validCacheOutput(final CacheEntry entry, final CandidateWork candidate) {
    if (entry.trimmedPath() == null) {
      return !candidate.isMultiRelease()
          && entry.originalPhysicalEntries() == null
          && entry.trimmedPhysicalEntries() == null
          && entry.retainedClasses() == entry.totalClasses()
          && entry.originalSha1() == null
          && entry.trimmedSha256() == null
          && entry.trimmedSha1() == null;
    }
    return validDigest(entry.originalSha1(), 40)
        && validDigest(entry.trimmedSha256(), 64)
        && validDigest(entry.trimmedSha1(), 40)
        && entry.originalPhysicalEntries() != null
        && entry.trimmedPhysicalEntries() != null
        && entry.originalPhysicalEntries() >= 0
        && entry.trimmedPhysicalEntries() >= 0
        && (entry.retainedClasses() < entry.totalClasses() || candidate.isMultiRelease());
  }

  private static Set<String> normalizedNames(final Set<String> names) {
    return names.stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toSet());
  }

  private static boolean validDigest(final String value, final int length) {
    return value != null && value.matches("[0-9a-f]{" + length + "}");
  }

  private static int physicalEntryCount(final Path archivePath) throws IOException {
    int count = 0;
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final var entries = archive.entries();
      while (entries.hasMoreElements()) {
        entries.nextElement();
        count = Math.addExact(count, 1);
      }
    } catch (final ArithmeticException exception) {
      throw new IOException("Archive entry count overflowed: " + archivePath, exception);
    }
    return count;
  }

  private static void storeCache(final Path manifestPath, final CacheManifest manifest)
      throws IOException {
    final Path parent = manifestPath.getParent();
    if (parent == null) {
      throw new IOException("Trim cache manifest has no parent directory: " + manifestPath);
    }
    Files.createDirectories(parent);
    final Path temporary = Files.createTempFile(parent, ".trim-cache-", ".json.tmp");
    try {
      JSON.writeValue(temporary.toFile(), manifest);
      Files.move(
          temporary,
          manifestPath,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static String sha256(final Path path) throws IOException {
    try (InputStream input = Files.newInputStream(path)) {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final byte[] buffer = new byte[8192];
      while (true) {
        final int count = input.read(buffer);
        if (count < 0) {
          return HexFormat.of().formatHex(digest.digest());
        }
        digest.update(buffer, 0, count);
      }
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String hash(final byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static int releaseFromOptions(final List<String> options, final Path javaHome)
      throws IOException {
    for (int index = 0; index < options.size() - 1; index++) {
      if ("--release".equals(options.get(index))) {
        final String value = options.get(index + 1);
        return parseRelease(value);
      }
    }
    if (options.contains("-source") && options.contains("-target")) {
      return currentJdkRelease(javaHome);
    }
    throw new IOException("Cannot determine effective Java compiler release for JAR trimming");
  }

  private static int parseRelease(final String value) throws IOException {
    final String normalized = value.startsWith("1.") ? value.substring(2) : value;
    try {
      return Integer.parseInt(normalized);
    } catch (final NumberFormatException exception) {
      throw new IOException("Unsupported Java compiler release: " + value, exception);
    }
  }

  private static int currentJdkRelease(final Path javaHome) throws IOException {
    final Path releaseFile = javaHome.resolve("release");
    if (!Files.isRegularFile(releaseFile)) {
      throw new IOException("Cannot identify the executing JDK release: " + javaHome);
    }
    for (final String line : Files.readAllLines(releaseFile)) {
      if (line.startsWith("JAVA_VERSION=\"")) {
        final String version = line.substring("JAVA_VERSION=\"".length()).replace("\"", "");
        final int dot = version.indexOf('.');
        final String feature = dot < 0 ? version : version.substring(0, dot);
        try {
          return Integer.parseInt(feature);
        } catch (final NumberFormatException exception) {
          throw new IOException("Unsupported executing JDK version: " + version, exception);
        }
      }
    }
    throw new IOException("Cannot identify the executing JDK release: " + javaHome);
  }

  private static String safeFilePart(final String value) {
    if (value == null || value.isBlank()) {
      return "unnamed";
    }
    return value.replaceAll("[^A-Za-z0-9._-]", "_");
  }
}
