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
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.jar.JarFile;
import org.apache.maven.artifact.DependencyResolutionRequiredException;
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
  private static final String DEFAULT_BUILD_DIRECTORY = "target";
  private static final String ELIDED_ARTIFACTS = "elided-artifacts";
  private static final String JAR_TYPE = "jar";
  private static final Set<String> TRIMMABLE_SCOPES = Set.of("compile", "runtime");
  private static final Set<String> ANALYSIS_LIBRARY_SCOPES =
      Set.of("compile", "runtime", "provided", "system");
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

  /** Cache schema used in the entry fingerprint and manifest envelope. */
  static final int CACHE_SCHEMA_VERSION = 1;

  /** Domain marker distinguishes this cache from incompatible pre-release drafts. */
  static final String CACHE_FORMAT_ID = "maven-dependency-elider-effective-output-cache";

  private static final String ENGINE_VERSION = "proguard-core-9.4.0";
  private static final int MAX_TRIM_WORKERS = 4;

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
      records = List.copyOf(records);
      multiReleasePassthroughArtifacts = List.copyOf(multiReleasePassthroughArtifacts);
      moduleInfoPassthroughArtifacts = List.copyOf(moduleInfoPassthroughArtifacts);
      configuredPassThroughArtifacts = List.copyOf(configuredPassThroughArtifacts);
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

  private record PlatformPools(ClassPool compiler, ClassPool runtime) {}

  private record CandidatePlan(
      List<Path> retainedInputPaths,
      List<CandidateWork> work,
      Map<String, List<CandidateWork>> ownersByClass,
      Map<String, Path> ownerByClass) {}

  private record CommonRootOwners(
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> byArtifact,
      Set<ArtifactCoordinate> droppedArtifacts) {}

  private record PassThroughPlan(
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
      String inventoryFingerprint,
      String directInventoryFingerprint,
      String operationFingerprint,
      String productionOutputFingerprint,
      Set<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean failOnUnsupportedMultiRelease,
      boolean failOnUnsupportedModuleInfo,
      TrimOutputGenerationPublisher.MoveOperation move) {
    private EffectiveOutputPlan {
      roots = immutableRootMap(roots);
      unchangedCoordinates = Set.copyOf(unchangedCoordinates);
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
    private final Path stagedGeneration;
    private final Path stagedManifest;
    private final List<PendingOutput> pendingOutputs = new ArrayList<>();

    private EffectiveOutputStaging(final Path stagedGeneration, final Path stagedManifest) {
      this.stagedGeneration = stagedGeneration;
      this.stagedManifest = stagedManifest;
    }

    private PreparedEffectiveOutputs prepareOutputs(
        final List<CandidateWork> work, final Map<Path, ArtifactDigests> inputDigests)
        throws IOException {
      final Map<CandidateWork, CacheEntry> entries = new java.util.HashMap<>();
      final List<ArtifactTrimRecord> records = new ArrayList<>();
      final List<CandidateWork> toSanitize = new ArrayList<>();
      for (final CandidateWork candidate : work) {
        final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
        if (analysis == null) {
          continue;
        }
        if (analysis.retainedClasses().size() == analysis.totalClasses()) {
          entries.put(candidate, cacheEntry(candidate, null, inputDigests));
          continue;
        }
        toSanitize.add(candidate);
      }
      final List<PendingOutput> prepared =
          mapParallel(
              toSanitize,
              candidate -> {
                final Path stagedOutput =
                    stagedGeneration.resolve(candidate.output().getFileName());
                final ArchiveSanitizer.PreparedOutput staged =
                    sanitizer.prepareWithProvenance(
                        candidate.snapshot().filePath(),
                        stagedOutput,
                        candidate.snapshot().coordinate(),
                        candidate.analysis(),
                        requiredInputDigest(inputDigests, candidate.snapshot().filePath()));
                return new PendingOutput(candidate, staged);
              });
      pendingOutputs.addAll(prepared);
      final List<ArtifactTrimRecord> stagedRecords =
          publishOutputs(
              pendingOutputs.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
      for (int index = 0; index < pendingOutputs.size(); index++) {
        final PendingOutput pending = pendingOutputs.get(index);
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
                staged.prunedClassBytes());
        records.add(record);
        entries.put(pending.candidate(), cacheEntry(pending.candidate(), record, inputDigests));
      }
      return new PreparedEffectiveOutputs(Map.copyOf(entries), List.copyOf(records));
    }

    @Override
    public void close() throws IOException {
      IOException cleanupFailure = null;
      for (final PendingOutput pending : pendingOutputs) {
        try {
          sanitizer.discard(pending.prepared());
        } catch (final IOException exception) {
          cleanupFailure = appendFailure(cleanupFailure, exception);
        }
      }
      try {
        Files.deleteIfExists(stagedManifest);
      } catch (final IOException exception) {
        cleanupFailure = appendFailure(cleanupFailure, exception);
      }
      try {
        deleteTree(stagedGeneration);
      } catch (final IOException exception) {
        cleanupFailure = appendFailure(cleanupFailure, exception);
      }
      if (cleanupFailure != null) {
        throw cleanupFailure;
      }
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
      List<String> bytecodeReferences,
      List<String> explicitRoots,
      List<String> explicitPassThroughCoordinates,
      boolean sourceRootsComplete,
      boolean failOnUnsupportedMultiRelease,
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
    roots.forEach((key, values) -> result.put(key, Set.copyOf(values)));
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
      Set<String> reachableLibraryClasses) {}

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
      boolean failOnUnsupportedModuleInfo) {}

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
      List<String> platformIdentities) {
    InMemoryAnalysis {
      candidateAnalyses = Map.copyOf(candidateAnalyses);
      candidateRoots = immutableSetMap(candidateRoots);
      reachableArtifacts = Set.copyOf(reachableArtifacts);
      javaHome = javaHome.toAbsolutePath().normalize();
      platformIdentities = List.copyOf(platformIdentities);
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
            options.failOnUnsupportedModuleInfo());
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
            effective.inventoryFingerprint(),
            prepared.directInputFingerprint(),
            effective.operationFingerprint(),
            prepared.productionOutputFingerprint(),
            prepared.bytecodeScan().map(BytecodeReferenceScan::referencedClasses).orElse(Set.of()),
            options.explicitTrimRoots(),
            options.explicitPassThroughArtifacts(),
            options.sourceRootsComplete(),
            options.failOnUnsupportedMultiRelease(),
            options.failOnUnsupportedModuleInfo(),
            move);
    final MavenProject project = request.project();
    final List<String> compileClasspath;
    try {
      compileClasspath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the effective compile classpath for JAR trimming", exception);
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.options(project, request.session(), compileClasspath);
    final Path javaHome = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
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
    final List<String> compileClasspath;
    try {
      compileClasspath = project.getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the effective compile classpath for JAR trimming", exception);
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.options(project, session, compileClasspath);
    final Path javaHome = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
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
    final List<MavenElisionService.ArtifactSnapshot> inventory =
        request.candidates().stream()
            .filter(snapshot -> JAR_TYPE.equals(snapshot.coordinate().type()))
            .toList();
    validateAnalysisInventory(inventory);
    final Set<ArtifactCoordinate> retainedCoordinates = request.retainedCoordinates();
    final List<MavenElisionService.ArtifactSnapshot> retainedLibraries =
        inventory.stream()
            .filter(snapshot -> retainedCoordinates.contains(snapshot.coordinate()))
            .filter(snapshot -> ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope()))
            .toList();
    final Map<MavenElisionService.ArtifactSnapshot, Path> analysisPaths =
        analysisPaths(request, inventory);
    final Map<Path, Set<String>> classesByPath = new java.util.LinkedHashMap<>();
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classesByArtifact =
        new java.util.LinkedHashMap<>();
    final Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass =
        new java.util.HashMap<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
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
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> requestedRoots =
        validateDiscoveredRoots(discoveredRoots, inventory, classesByPath);
    final Set<ArtifactCoordinate> layoutPassThroughCoordinates = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      if (!TRIMMABLE_SCOPES.contains(snapshot.coordinate().scope())) {
        continue;
      }
      if (passThroughCoordinate(request, snapshot)) {
        layoutPassThroughCoordinates.add(snapshot.coordinate());
      }
    }
    final List<MavenElisionService.ArtifactSnapshot> eligible =
        retainedLibraries.stream()
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
            .filter(snapshot -> !classesByArtifact.getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(
                snapshot ->
                    !passThroughIdentities.contains(artifactIdentity(snapshot.coordinate())))
            .toList();
    final List<MavenElisionService.ArtifactSnapshot> unchangedPrograms =
        retainedLibraries.stream()
            .filter(snapshot -> !classesByArtifact.getOrDefault(snapshot, Set.of()).isEmpty())
            .filter(snapshot -> !candidates.contains(snapshot))
            .toList();
    final Set<String> unchangedPassThroughClasses = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : configuredPassThrough) {
      unchangedPassThroughClasses.addAll(classesByArtifact.getOrDefault(snapshot, Set.of()));
    }
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      if (layoutPassThroughCoordinates.contains(snapshot.coordinate())) {
        unchangedPassThroughClasses.addAll(classesByArtifact.getOrDefault(snapshot, Set.of()));
      }
    }
    final List<Path> fullClasspath =
        inventory.stream()
            .filter(snapshot -> ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope()))
            .map(
                snapshot ->
                    analysisPaths.getOrDefault(
                        snapshot, snapshot.filePath().toAbsolutePath().normalize()))
            .toList();
    final List<String> compileClasspath;
    try {
      compileClasspath = request.project().getCompileClasspathElements();
    } catch (final DependencyResolutionRequiredException exception) {
      throw new IOException(
          "Cannot resolve the effective compile classpath for analysis", exception);
    }
    final List<String> compilerOptions =
        MavenCompilerSettings.options(request.project(), request.session(), compileClasspath);
    final Path javaHome = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
    final int release = releaseFromOptions(compilerOptions, javaHome);
    final int runtimeRelease = Runtime.version().feature();
    final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots = new ArrayList<>(2);
    try (JdkPlatformContext platformContext = new JdkPlatformContext(javaHome)) {
      platformSnapshots.add(platformContext.snapshot(release));
      if (runtimeRelease != release) {
        platformSnapshots.add(platformContext.snapshot(runtimeRelease));
      }
    }
    final PlatformPools pools = readPlatformPools(platformSnapshots, release, runtimeRelease);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final TrimAnalysisSession analysisSession = new TrimAnalysisSession(trimmer);
    final Set<String> commonRoots = commonRoots(request);
    final Set<String> platformClasses = platformClasses(pools);
    final CommonRootOwners commonRootOwners =
        commonRootOwners(
            commonRoots,
            ownerByClass,
            request,
            retainedCoordinates,
            classesByArtifact,
            platformClasses);
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> dynamicRootsByOwner =
        new java.util.LinkedHashMap<>();
    final Set<ArtifactCoordinate> dynamicRootsInDroppedArtifacts = new LinkedHashSet<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      for (final String root : dynamicRoots(request, snapshot.filePath())) {
        final MavenElisionService.ArtifactSnapshot owner = ownerByClass.get(root);
        if (owner == null) {
          if (request.projectOutputClasses().contains(root) || platformClasses.contains(root)) {
            continue;
          }
          dynamicRootsInDroppedArtifacts.addAll(
              inventory.stream()
                  .filter(candidate -> !retainedCoordinates.contains(candidate.coordinate()))
                  .map(MavenElisionService.ArtifactSnapshot::coordinate)
                  .toList());
          continue;
        }
        if (retainedCoordinates.contains(owner.coordinate())) {
          if (eligible.contains(owner)) {
            dynamicRootsByOwner.computeIfAbsent(owner, ignored -> new TreeSet<>()).add(root);
          }
        } else {
          dynamicRootsInDroppedArtifacts.add(owner.coordinate());
        }
      }
    }
    final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots =
        new java.util.LinkedHashMap<>();
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedCandidates = new java.util.LinkedHashMap<>();
    for (final MavenElisionService.ArtifactSnapshot candidate : candidates) {
      final Path path = candidate.filePath().toAbsolutePath().normalize();
      final Set<String> roots = new TreeSet<>(requestedRoots.getOrDefault(candidate, Set.of()));
      roots.addAll(commonRootOwners.byArtifact().getOrDefault(candidate, Set.of()));
      roots.addAll(dynamicRootsByOwner.getOrDefault(candidate, Set.of()));
      if (roots.isEmpty()) {
        roots.addAll(classesByArtifact.getOrDefault(candidate, Set.of()));
      }
      candidateRoots.put(candidate, roots);
      final List<Path> siblings =
          fullClasspath.stream().filter(value -> !value.equals(path)).toList();
      preparedCandidates.put(
          candidate,
          analysisSession.prepareWithUnchangedPassThroughLibraries(
              path, siblings, pools.compiler(), unchangedPassThroughClasses));
    }
    final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        preparedPrograms = new java.util.LinkedHashMap<>();
    for (final MavenElisionService.ArtifactSnapshot program : unchangedPrograms) {
      final Path path =
          analysisPaths.getOrDefault(program, program.filePath().toAbsolutePath().normalize());
      final List<Path> siblings =
          fullClasspath.stream().filter(value -> !value.equals(path)).toList();
      final DependencyJarTrimmer.PreparedAnalysis preparedProgram =
          skippedProgramCoordinates.contains(program.coordinate())
              ? analysisSession.prepareUnchangedPassThrough(
                  path, siblings, pools.runtime(), unchangedPassThroughClasses)
              : analysisSession.prepareWithUnchangedPassThroughLibraries(
                  path, siblings, pools.runtime(), unchangedPassThroughClasses);
      preparedPrograms.put(program, preparedProgram);
    }
    final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> finalAnalyses =
        new java.util.LinkedHashMap<>();
    final Set<ArtifactCoordinate> reachableArtifacts =
        new LinkedHashSet<>(commonRootOwners.droppedArtifacts());
    reachableArtifacts.addAll(dynamicRootsInDroppedArtifacts);
    int analysisRuns = 0;
    boolean rootsChanged;
    do {
      rootsChanged = false;
      for (final Map.Entry<
              MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          entry : preparedPrograms.entrySet()) {
        final Set<String> roots = classesByArtifact.get(entry.getKey());
        final DependencyJarTrimmer.TrimAnalysis analysis = entry.getValue().analyze(roots);
        analysisRuns++;
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                ownerByClass,
                candidates,
                candidateRoots,
                reachableArtifacts,
                retainedCoordinates,
                entry.getKey());
      }
      finalAnalyses.clear();
      for (final Map.Entry<
              MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          entry : preparedCandidates.entrySet()) {
        final MavenElisionService.ArtifactSnapshot candidate = entry.getKey();
        final DependencyJarTrimmer.TrimAnalysis analysis =
            entry.getValue().analyze(candidateRoots.get(candidate));
        analysisRuns++;
        finalAnalyses.put(candidate.coordinate(), analysis);
        rootsChanged |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(),
                ownerByClass,
                candidates,
                candidateRoots,
                reachableArtifacts,
                retainedCoordinates,
                candidate);
      }
    } while (rootsChanged);
    return inMemoryResult(
        finalAnalyses,
        candidateRoots,
        reachableArtifacts,
        analysisRuns,
        release,
        runtimeRelease,
        javaHome,
        platformSnapshots);
  }

  private static void validateAnalysisInventory(
      final List<MavenElisionService.ArtifactSnapshot> inventory) throws IOException {
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
          MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses(snapshot.filePath());
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
    final boolean multiRelease =
        MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses(snapshot.filePath());
    final boolean moduleInfo =
        MultiReleaseLibraryProjection.hasRootModuleDescriptor(snapshot.filePath());
    if (!request.retainedCoordinates().contains(snapshot.coordinate())) {
      return multiRelease || moduleInfo;
    }
    if (multiRelease && request.failOnUnsupportedMultiRelease()) {
      throw new IOException(
          "Unsupported multi-release implementation classes in " + snapshot.coordinate());
    }
    if (moduleInfo && request.failOnUnsupportedModuleInfo()) {
      throw new IOException(
          "Unsupported root module descriptor in retained classpath JAR: " + snapshot.coordinate());
    }
    return multiRelease || moduleInfo;
  }

  private static Map<MavenElisionService.ArtifactSnapshot, Set<String>> validateDiscoveredRoots(
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

  private static Set<String> commonRoots(final TrimRequest request) {
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

  private static Set<String> dynamicRoots(final TrimRequest request, final Path path)
      throws IOException {
    final DependencyDynamicRoots.RootScan scan = request.scanInputs().dynamicRootScans().get(path);
    if (scan == null) {
      throw new IOException("Missing dynamic-root scan for full inventory JAR: " + path);
    }
    return scan.roots().stream()
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

  private static InMemoryAnalysis inMemoryResult(
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses,
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots,
      final Set<ArtifactCoordinate> reachableArtifacts,
      final int analysisRuns,
      final int compilerRelease,
      final int runtimeRelease,
      final Path javaHome,
      final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {
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
            .toList());
  }

  private static Map<ArtifactCoordinate, Set<String>> immutableSetMap(
      final Map<ArtifactCoordinate, Set<String>> values) {
    final Map<ArtifactCoordinate, Set<String>> result = new java.util.LinkedHashMap<>();
    values.forEach((coordinate, roots) -> result.put(coordinate, Set.copyOf(roots)));
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
            runtimeRelease,
            release,
            CACHE_SCHEMA_VERSION,
            ENGINE_VERSION,
            platformContext,
            effectiveCacheContext(request, effectiveOutput));
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
            runtimeRelease,
            release,
            CACHE_SCHEMA_VERSION,
            ENGINE_VERSION,
            platformContext,
            null);
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
        analyze(plan, passThroughPlan, analysisLibraryDirectory, runtimeRelease, platformPools);

    final ArchiveSanitizer sanitizer = new ArchiveSanitizer();
    final Map<CandidateWork, CacheEntry> entriesByCandidate = new java.util.HashMap<>();
    final List<PendingOutput> pendingOutputs = new ArrayList<>();
    try {
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
              candidate -> {
                final ArchiveSanitizer.PreparedOutput staged =
                    sanitizer.prepareWithProvenance(
                        candidate.snapshot().filePath(),
                        candidate.output(),
                        candidate.snapshot().coordinate(),
                        candidate.analysis(),
                        requiredInputDigest(
                            fingerprintSnapshot.inputDigests(), candidate.snapshot().filePath()));
                return new PendingOutput(candidate, staged);
              });
      pendingOutputs.addAll(prepared);
      final List<ArtifactTrimRecord> publishedRecords =
          publishOutputs(
              pendingOutputs.stream().map(PendingOutput::prepared).toList(), sanitizer::publish);
      for (int index = 0; index < pendingOutputs.size(); index++) {
        final PendingOutput pending = pendingOutputs.get(index);
        final ArtifactTrimRecord record = publishedRecords.get(index);
        records.add(record);
        entriesByCandidate.put(
            pending.candidate(),
            cacheEntry(pending.candidate(), record, fingerprintSnapshot.inputDigests()));
      }
    } finally {
      for (final PendingOutput pending : pendingOutputs) {
        sanitizer.discard(pending.prepared());
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
            staging.prepareOutputs(work, fingerprint.inputDigests());
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

  private static IOException appendFailure(final IOException previous, final IOException next) {
    if (previous == null) {
      return next;
    }
    previous.addSuppressed(next);
    return previous;
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
      final PlatformPools platformPools)
      throws IOException {
    final AnalysisLibraries libraries =
        analysisLibraries(passThroughPlan, analysisLibraryDirectory, runtimeRelease);
    final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
    final TrimAnalysisSession session = new TrimAnalysisSession(trimmer);
    validateUniqueAnalysisClasses(candidatePlan, libraries.skippedPrograms());
    final int passThroughRuns =
        analyzePassThroughPrograms(candidatePlan, libraries, session, platformPools.runtime());
    return passThroughRuns
        + analyzeCandidateFixedPoint(candidatePlan, libraries, session, platformPools.compiler());
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
      final ClassPool runtimePlatform)
      throws IOException {
    final List<SkippedProgram> skipped = libraries.skippedPrograms();
    if (skipped.isEmpty()) {
      return 0;
    }
    final List<DependencyJarTrimmer.TrimAnalysis> analyses =
        mapParallel(
            skipped,
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
      final ClassPool platform)
      throws IOException {
    int analysisRuns = 0;
    final List<CandidateWork> work = candidatePlan.work();
    final List<DependencyJarTrimmer.PreparedAnalysis> preparedList =
        mapParallel(
            work,
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
              work, candidate -> candidateAnalyses.get(candidate).analyze(candidate.roots()));
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

  private static Path analysisLibraryDirectory(final MavenProject project) {
    return project.getBuild() == null || project.getBuild().getDirectory() == null
        ? Path.of(DEFAULT_BUILD_DIRECTORY, ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize()
        : Path.of(project.getBuild().getDirectory(), ELIDED_ARTIFACTS, ".analysis-libraries")
            .toAbsolutePath()
            .normalize();
  }

  private static PassThroughPlan passThroughPlan(final TrimRequest request) throws IOException {
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
    for (final MavenElisionService.ArtifactSnapshot snapshot : retainedLibraries) {
      if (MultiReleaseLibraryProjection.hasUnsupportedVersionedClasses(snapshot.filePath())) {
        if (request.failOnUnsupportedMultiRelease()) {
          throw new IOException(
              "Unsupported multi-release implementation classes in " + snapshot.coordinate());
        }
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
    for (final MavenElisionService.ArtifactSnapshot candidate : retained) {
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
    for (final MavenElisionService.ArtifactSnapshot candidate : retained) {
      if (effectiveOutput.unchangedCoordinates().contains(candidate.coordinate())) {
        continue;
      }
      final Set<String> candidateClasses = classesFor(candidate, classesByArtifact);
      if (candidateClasses.isEmpty()) {
        continue;
      }
      final Set<String> roots = rootsBySnapshot.get(candidate);
      if (roots == null) {
        throw new IOException("Effective analysis has no roots for " + candidate.coordinate());
      }
      final Path output = outputPath(project, candidate.coordinate());
      if (!distinctOutputs.add(output)) {
        throw new IOException("Distinct effective candidates share output path: " + output);
      }
      work.add(new CandidateWork(candidate, candidateClasses, roots, output));
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
              .equals(candidate.roots())) {
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
        .sorted(
            Comparator.comparing(MavenElisionService.ArtifactSnapshot::coordinate)
                .thenComparing(snapshot -> snapshot.filePath().toAbsolutePath().normalize()))
        .toList();
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
            output.bytecodeReferences().stream().sorted().toList(),
            output.explicitRoots().stream().sorted().toList(),
            output.explicitPassThroughCoordinates().stream().sorted().toList(),
            output.sourceRootsComplete(),
            output.failOnUnsupportedMultiRelease(),
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

  private static Set<String> classNames(final Path archivePath) throws IOException {
    final Set<String> classNames = new TreeSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final var entries = archive.entries();
      while (entries.hasMoreElements()) {
        final String name = entries.nextElement().getName();
        if (name.endsWith(".class")
            && !"module-info.class".equals(name)
            && !name.endsWith("/module-info.class")) {
          classNames.add(name.substring(0, name.length() - ".class".length()).replace('/', '.'));
        }
      }
    }
    return Set.copyOf(classNames);
  }

  private static Path outputPath(final MavenProject project, final ArtifactCoordinate coordinate) {
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
    private Path output;
    private DependencyJarTrimmer.TrimAnalysis analysis;

    private CandidateWork(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> classes,
        final Set<String> roots,
        final Path output) {
      this.snapshot = snapshot;
      this.classes = Set.copyOf(classes);
      this.roots = new TreeSet<>(roots.isEmpty() ? classes : roots);
      this.output = output;
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
  private interface TrimmerWorkItem<T, R> {
    R execute(T item) throws IOException;
  }

  private static int trimParallelism(final int workSize) {
    if (workSize <= 1) {
      return 1;
    }
    final int available = Runtime.getRuntime().availableProcessors();
    return Math.max(1, Math.min(available, MAX_TRIM_WORKERS));
  }

  @SuppressWarnings({"PMD.DoNotUseThreads", "PMD.PreserveStackTrace"})
  private static <T, R> List<R> mapParallel(final List<T> items, final TrimmerWorkItem<T, R> task)
      throws IOException {
    if (items.isEmpty()) {
      return List.of();
    }
    final int parallelism = trimParallelism(items.size());
    if (parallelism <= 1 || items.size() == 1) {
      final List<R> results = new ArrayList<>(items.size());
      for (final T item : items) {
        results.add(task.execute(item));
      }
      return List.copyOf(results);
    }
    try (ExecutorService executor =
        Executors.newFixedThreadPool(
            Math.min(items.size(), parallelism),
            runnable -> {
              final Thread thread = new Thread(runnable, "dependency-elider-worker");
              thread.setDaemon(true);
              return thread;
            })) {
      final List<Future<R>> futures = new ArrayList<>(items.size());
      for (final T item : items) {
        futures.add(executor.submit(() -> task.execute(item)));
      }
      final List<R> results = new ArrayList<>(items.size());
      for (final Future<R> future : futures) {
        try {
          results.add(future.get());
        } catch (final ExecutionException e) {
          final Throwable cause = e.getCause();
          if (cause instanceof IOException ioException) {
            throw ioException;
          }
          throw new IOException("Parallel trimming task failed", cause);
        }
      }
      return List.copyOf(results);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while executing parallel trimming tasks", e);
    }
  }

  private static FingerprintSnapshot fingerprint(
      final List<CandidateWork> candidates,
      final List<Path> allRetainedInputs,
      final Set<String> skippedArtifactIdentities,
      final int runtimeRelease,
      final int release,
      final int schemaVersion,
      final String engineVersion,
      final JdkPlatformContext platformContext,
      final String outputContext)
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
    if (outputContext != null) {
      candidateIdentities.add("effective-output-context:" + outputContext);
    }
    candidateIdentities.add("runtime-release:" + runtimeRelease);
    final List<JdkPlatformContext.PlatformSnapshot> platformSnapshots = new ArrayList<>(2);
    platformSnapshots.add(platformContext.snapshot(release));
    if (runtimeRelease != release) {
      platformSnapshots.add(platformContext.snapshot(runtimeRelease));
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
            release,
            schemaVersion,
            engineVersion,
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
    final ClassPool compiler = reader.read(platformSnapshot(snapshots, compilerRelease));
    final ClassPool runtime =
        runtimeRelease == compilerRelease
            ? compiler
            : reader.read(platformSnapshot(snapshots, runtimeRelease));
    return new PlatformPools(compiler, runtime);
  }

  private static String artifactIdentity(final ArtifactCoordinate coordinate) {
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
    return new CacheEntry(
        candidate.snapshot().filePath().toAbsolutePath().normalize().toString(),
        originalDigests.sha256(),
        record == null ? null : originalDigests.sha1(),
        record == null ? null : record.trimmedPath().toString(),
        record == null ? null : record.trimmedSha256(),
        record == null ? null : record.trimmedSha1(),
        analysis.totalClasses(),
        analysis.retainedClasses().size(),
        record == null ? 0L : record.prunedClassBytes(),
        candidate.roots(),
        analysis.retainedClasses(),
        analysis.reachableLibraryClasses());
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
          || !entry.trimmedSha1().equals(outputDigests.sha1())) {
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
              entry.prunedClassBytes()));
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
    if (entry == null
        || !validDigest(entry.originalSha256(), 64)
        || entry.roots() == null
        || entry.roots().contains(null)
        || entry.retainedClassNames() == null
        || entry.retainedClassNames().contains(null)
        || entry.prunedClassBytes() == null
        || entry.prunedClassBytes() < 0
        || entry.reachableLibraryClasses() == null
        || entry.reachableLibraryClasses().contains(null)
        || entry.totalClasses() != candidate.classes().size()
        || entry.retainedClasses() < 0
        || entry.retainedClasses() > entry.totalClasses()
        || entry.retainedClassNames().size() != entry.retainedClasses()
        || !candidate.classes().containsAll(entry.roots())) {
      return false;
    }
    final DependencyJarTrimmer.TrimAnalysis analysis = candidate.analysis();
    if (analysis != null
        && (!candidate.roots().equals(entry.roots())
            || !candidate.roots().equals(normalizedNames(analysis.roots()))
            || !entry.retainedClassNames().equals(analysis.retainedClasses())
            || !entry.reachableLibraryClasses().equals(analysis.reachableLibraryClasses()))) {
      return false;
    }
    for (final String retainedClass : entry.retainedClassNames()) {
      if (!candidate.classes().contains(retainedClass.replace('/', '.'))) {
        return false;
      }
    }
    if (entry.trimmedPath() == null) {
      return entry.retainedClasses() == entry.totalClasses()
          && entry.originalSha1() == null
          && entry.trimmedSha256() == null
          && entry.trimmedSha1() == null;
    }
    return validDigest(entry.originalSha1(), 40)
        && validDigest(entry.trimmedSha256(), 64)
        && validDigest(entry.trimmedSha1(), 40)
        && entry.retainedClasses() < entry.totalClasses();
  }

  private static Set<String> normalizedNames(final Set<String> names) {
    return names.stream()
        .map(name -> name.replace('/', '.'))
        .collect(java.util.stream.Collectors.toSet());
  }

  private static boolean validDigest(final String value, final int length) {
    return value != null && value.matches("[0-9a-f]{" + length + "}");
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
