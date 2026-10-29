/* WHY: Coordinates release-specific projections so MRJAR candidate and sibling closure are
 * computed against the same implementation bodies that can run at each supported release. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.MavenDependencyTrimmer.ArtifactRootKey;
import io.github.spockz.elider.plugin.MavenDependencyTrimmer.InMemoryAnalysis;
import io.github.spockz.elider.plugin.MavenDependencyTrimmer.PassThroughPlan;
import io.github.spockz.elider.plugin.MavenDependencyTrimmer.TrimRequest;
import io.github.spockz.elider.trimmer.DependencyJarTrimmer;
import io.github.spockz.elider.trimmer.JdkApiClassPoolReader;
import io.github.spockz.elider.trimmer.JdkPlatformContext;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import io.github.spockz.elider.trimmer.TrimAnalysisSession;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import proguard.classfile.ClassPool;

/** Coordinates release-specific candidate and sibling closure analysis. */
// WHY: The coordinator shares tier-bound state across its phases.
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.UseConcurrentHashMap",
  "PMD.CouplingBetweenObjects"
})
final class MultiReleaseTierAnalyzer {
  /** Zero-target analysis retained for candidates with no target-visible roots. */
  private static final DependencyJarTrimmer.TrimAnalysis EMPTY_ANALYSIS =
      new DependencyJarTrimmer.TrimAnalysis(0, Set.of(), Set.of(), Set.of());

  /** Shared request keeps release views bound to one operation. */
  private final TrimRequest request;

  /** Discovered roots retain logical names as artifacts are promoted. */
  private final Map<ArtifactRootKey, Set<String>> discoveredRoots;

  /** Forced unchanged artifacts still seed sibling analysis. */
  private final Set<ArtifactCoordinate> forcedUnchanged;

  /** The compiler target and runtime bound select the views to verify. */
  private final int targetRelease;

  /** Runtime bound adds upper implementation bodies to the closure. */
  private final int runtimeRelease;

  /** Platform snapshots use the compiler's JDK home. */
  private final Path javaHome;

  private MultiReleaseTierAnalyzer(
      final TrimRequest request,
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final int targetRelease,
      final int runtimeRelease,
      final Path javaHome) {
    this.request = request;
    this.discoveredRoots = discoveredRoots;
    this.forcedUnchanged = forcedUnchanged;
    this.targetRelease = targetRelease;
    this.runtimeRelease = runtimeRelease;
    this.javaHome = javaHome;
  }

  static InMemoryAnalysis analyze(
      final TrimRequest request,
      final Map<ArtifactRootKey, Set<String>> discoveredRoots,
      final Set<ArtifactCoordinate> forcedUnchanged,
      final int targetRelease,
      final int runtimeRelease,
      final Path javaHome)
      throws IOException {
    return new MultiReleaseTierAnalyzer(
            request, discoveredRoots, forcedUnchanged, targetRelease, runtimeRelease, javaHome)
        .analyze();
  }

  private InMemoryAnalysis analyze() throws IOException {
    final InventoryBuilder inventoryBuilder = new InventoryBuilder();
    Inventory inventory = inventoryBuilder.readInventory();
    final PlatformPlan platforms = inventoryBuilder.readPlatforms(inventory.tiers());
    inventory = inventory.withPlatformSnapshots(platforms.snapshots());
    final List<TierContext> projections = inventoryBuilder.projectInventory(inventory, platforms);
    final RootPlanner rootPlanner = new RootPlanner();
    final RootPlan roots = rootPlanner.findRoots(inventory, projections, platforms.byRelease());
    final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates =
        new CandidatePlanner()
            .createCandidates(roots, projections, inventory.multiReleaseCandidates());
    final List<TierContext> prepared =
        new AnalysisPreparer().prepareContexts(inventory, projections, roots, candidates);
    final ClosureAnalyzer closureAnalyzer = new ClosureAnalyzer();
    final ClosureResult closure = closureAnalyzer.analyzeToFixedPoint(prepared, roots, candidates);
    return closureAnalyzer.createResult(inventory, roots, candidates, closure);
  }

  private static Set<String> classesInTargetTier(
      final MavenElisionService.ArtifactSnapshot snapshot, final List<TierContext> contexts) {
    for (final TierContext context : contexts) {
      if (context.release() == context.targetRelease()) {
        return context.classesOf(snapshot);
      }
    }
    return Set.of();
  }

  private List<Path> tierSiblings(
      final List<MavenElisionService.ArtifactSnapshot> inventory,
      final TierContext context,
      final MavenElisionService.ArtifactSnapshot candidate) {
    final List<Path> siblings = new ArrayList<>();
    for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
      if (MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(snapshot.coordinate().scope())
          && !snapshot.equals(candidate)) {
        final Path path = context.pathFor(snapshot);
        if (path != null) {
          siblings.add(path);
        }
      }
    }
    return siblings;
  }

  /** Creates source inventories and release-specific classpath projections. */
  // WHY: Inventory creation binds archive and platform collaborators.
  @SuppressWarnings("PMD.CouplingBetweenObjects")
  private final class InventoryBuilder {
    /** Uses the enclosing operation bounds for each archive projection. */
    private InventoryBuilder() {}

    private Inventory readInventory() throws IOException {
      final List<MavenElisionService.ArtifactSnapshot> inventory =
          request.candidates().stream()
              .filter(
                  snapshot -> MavenDependencyTrimmer.JAR_TYPE.equals(snapshot.coordinate().type()))
              .toList();
      MavenDependencyTrimmer.validateAnalysisInventory(inventory);
      final PassThroughPlan passThrough = MavenDependencyTrimmer.passThroughPlan(request);
      final Path projectionDirectory =
          MavenDependencyTrimmer.analysisLibraryDirectory(request.project());
      final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease =
          new LinkedHashMap<>();
      final Set<Integer> tiers = new TreeSet<>();
      tiers.add(targetRelease);
      tiers.add(runtimeRelease);
      final Map<Path, Set<String>> classesBySourcePath = new LinkedHashMap<>();
      for (final MavenElisionService.ArtifactSnapshot snapshot : inventory) {
        final Path source = snapshot.filePath().toAbsolutePath().normalize();
        classesBySourcePath.put(source, MavenDependencyTrimmer.logicalClassNames(source));
        if (!MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)) {
          continue;
        }
        addAnalyzedTiers(source, tiers);
        addMultiReleaseCandidate(snapshot, source, passThrough, projectionDirectory, multiRelease);
      }
      return new Inventory(
          inventory,
          passThrough,
          projectionDirectory,
          Map.copyOf(classesBySourcePath),
          Map.copyOf(multiRelease),
          tiers.stream().sorted().toList());
    }

    private void addAnalyzedTiers(final Path source, final Set<Integer> tiers) throws IOException {
      for (final int release : MultiReleaseClassInventory.versionedClassReleases(source)) {
        if (release > targetRelease && release <= runtimeRelease) {
          tiers.add(release);
        }
      }
    }

    private void addMultiReleaseCandidate(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Path source,
        final PassThroughPlan passThrough,
        final Path projectionDirectory,
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> candidates)
        throws IOException {
      if (!passThrough.retained().contains(snapshot)
          || MultiReleaseLibraryProjection.hasRootModuleDescriptor(source)) {
        return;
      }
      final Path targetProjection =
          MultiReleaseLibraryProjection.create(
              source, snapshot.coordinate(), projectionDirectory, targetRelease);
      final Set<String> targetClasses = MavenDependencyTrimmer.classNames(targetProjection);
      final MultiReleaseArchivePlan.PluginView view =
          MultiReleaseArchivePlan.create(source, targetRelease, Set.of(), Set.of()).pluginView();
      final Set<String> viewClasses = dottedNames(view.targetPresentClasses());
      if (!viewClasses.equals(targetClasses)) {
        throw new IOException(
            "MRJAR target projection and archive plan disagree for " + snapshot.coordinate());
      }
      candidates.put(
          snapshot,
          new MultiReleaseCandidateInfo(
              dottedNames(view.requiredRootClasses()),
              MultiReleaseClassInventory.classNamesAboveRelease(source, targetRelease)));
    }

    private static Set<String> dottedNames(final Set<String> names) {
      return names.stream()
          .map(name -> name.replace('/', '.'))
          .collect(java.util.stream.Collectors.toUnmodifiableSet());
    }

    private PlatformPlan readPlatforms(final List<Integer> tiers) throws IOException {
      final List<JdkPlatformContext.PlatformSnapshot> snapshots = new ArrayList<>();
      try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
        for (final int tier : tiers) {
          snapshots.add(context.snapshot(tier));
        }
      }
      final JdkApiClassPoolReader reader = new JdkApiClassPoolReader();
      final Map<Integer, ClassPool> pools = new LinkedHashMap<>();
      for (final JdkPlatformContext.PlatformSnapshot snapshot : snapshots) {
        pools.put(snapshot.effectiveRelease(), reader.read(snapshot));
      }
      return new PlatformPlan(snapshots, Map.copyOf(pools));
    }

    private List<TierContext> projectInventory(
        final Inventory inventory, final PlatformPlan platforms) throws IOException {
      final List<TierContext> contexts = new ArrayList<>();
      for (final int tier : inventory.tiers()) {
        contexts.add(projectTier(inventory, platforms.byRelease().get(tier), tier));
      }
      return List.copyOf(contexts);
    }

    private TierContext projectTier(
        final Inventory inventory, final ClassPool platform, final int release) throws IOException {
      final Map<MavenElisionService.ArtifactSnapshot, Path> paths = new LinkedHashMap<>();
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classes = new LinkedHashMap<>();
      final Map<String, MavenElisionService.ArtifactSnapshot> owners = new HashMap<>();
      for (final MavenElisionService.ArtifactSnapshot snapshot : inventory.snapshots()) {
        if (!MavenDependencyTrimmer.ANALYSIS_LIBRARY_SCOPES.contains(
            snapshot.coordinate().scope())) {
          continue;
        }
        addTierArtifact(inventory.projectionDirectory(), release, snapshot, paths, classes);
        assignTierOwners(classes.get(snapshot), snapshot, owners, release);
      }
      return new TierContext(
          release,
          targetRelease,
          inventory.multiReleaseCandidates(),
          paths,
          classes,
          owners,
          Map.of(),
          Map.of(),
          platform);
    }

    private void addTierArtifact(
        final Path projectionDirectory,
        final int release,
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Map<MavenElisionService.ArtifactSnapshot, Path> paths,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> classes)
        throws IOException {
      final Path source = snapshot.filePath().toAbsolutePath().normalize();
      final boolean needsProjection =
          MultiReleaseClassInventory.hasUnsupportedVersionedClasses(source)
              || MultiReleaseLibraryProjection.hasRootModuleDescriptor(source);
      final Path analysisPath =
          needsProjection
              ? MultiReleaseLibraryProjection.create(
                  source, snapshot.coordinate(), projectionDirectory, release)
              : source;
      paths.put(snapshot, analysisPath);
      classes.put(snapshot, MavenDependencyTrimmer.classNames(analysisPath));
    }

    private static void assignTierOwners(
        final Set<String> names,
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Map<String, MavenElisionService.ArtifactSnapshot> owners,
        final int release)
        throws IOException {
      for (final String name : names) {
        final MavenElisionService.ArtifactSnapshot previous = owners.putIfAbsent(name, snapshot);
        if (previous != null && !previous.equals(snapshot)) {
          throw new IOException("Duplicate class owner in tier " + release + ": " + name);
        }
      }
    }
  }

  /** Resolves user, trace and sibling roots onto their owning artifacts. */
  private final class RootPlanner {
    /** Resolves roots against the release-specific class ownership maps. */
    private RootPlanner() {}

    private RootPlan findRoots(
        final Inventory inventory,
        final List<TierContext> projections,
        final Map<Integer, ClassPool> platforms)
        throws IOException {
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> requested =
          MavenDependencyTrimmer.validateDiscoveredRoots(
              discoveredRoots, inventory.snapshots(), inventory.classesBySourcePath());
      final Set<String> platformNames = platformClassNames(platforms.values());
      validateStrictRoots(projections, platformNames);
      final List<MavenElisionService.ArtifactSnapshot> snapshots =
          findCandidateSnapshots(
              inventory.passThrough(), projections, inventory.multiReleaseCandidates());
      final Set<MavenElisionService.ArtifactSnapshot> candidates = Set.copyOf(snapshots);
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots =
          emptyCandidateRoots(snapshots);
      final Set<ArtifactCoordinate> reachable = new LinkedHashSet<>();
      final RootResolution resolution = new RootResolution();
      resolution.addCommonRoots(
          MavenDependencyTrimmer.commonRoots(request), projections, candidates, roots, reachable);
      resolution.addRequestedRoots(requested, projections, candidates, roots);
      resolution.addDynamicRoots(
          inventory.passThrough().retainedLibraries(),
          projections,
          candidates,
          roots,
          reachable,
          platformNames);
      addRequiredTargetRoots(inventory.multiReleaseCandidates(), roots);
      return new RootPlan(snapshots, candidates, roots, reachable);
    }

    private Set<String> platformClassNames(final Iterable<ClassPool> platforms) {
      final Set<String> names = new HashSet<>();
      for (final ClassPool platform : platforms) {
        platform.classNames().forEachRemaining(name -> names.add(name.replace('/', '.')));
      }
      return names;
    }

    private void validateStrictRoots(
        final List<TierContext> projections, final Set<String> platformNames) throws IOException {
      final Set<String> roots = new HashSet<>();
      request.sourceRoots().forEach(root -> roots.add(root.replace('/', '.')));
      request.bytecodeRoots().forEach(root -> roots.add(root.replace('/', '.')));
      request.explicitRoots().forEach(root -> roots.add(root.replace('/', '.')));
      for (final String root : roots) {
        if (request.projectOutputClasses().contains(root) || platformNames.contains(root)) {
          continue;
        }
        if (projections.stream().noneMatch(context -> context.ownerOf(root) != null)) {
          throw new IOException("Required class root has no analyzed tier owner: " + root);
        }
      }
    }

    private List<MavenElisionService.ArtifactSnapshot> findCandidateSnapshots(
        final PassThroughPlan passThrough,
        final List<TierContext> projections,
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease) {
      return passThrough.retained().stream()
          .filter(snapshot -> !forcedUnchanged.contains(snapshot.coordinate()))
          .filter(
              snapshot ->
                  !classesInTargetTier(snapshot, projections).isEmpty()
                      || multiRelease.containsKey(snapshot))
          .sorted(MavenDependencyTrimmer.artifactSnapshotOrder())
          .toList();
    }

    private static Map<MavenElisionService.ArtifactSnapshot, Set<String>> emptyCandidateRoots(
        final List<MavenElisionService.ArtifactSnapshot> snapshots) {
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots = new LinkedHashMap<>();
      snapshots.forEach(snapshot -> roots.put(snapshot, new TreeSet<>()));
      return roots;
    }

    private static void addRequiredTargetRoots(
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots) {
      candidates.forEach(
          (snapshot, info) -> {
            final Set<String> candidateRoots = roots.get(snapshot);
            if (candidateRoots != null) {
              candidateRoots.addAll(info.requiredTargetRoots());
            }
          });
    }
  }

  /** Assigns discovered roots and references to tier-local artifact owners. */
  private final class RootResolution {
    /** Uses the same roots and artifact disposition as the parent analysis. */
    private RootResolution() {}

    private void addCommonRoots(
        final Set<String> roots,
        final List<TierContext> contexts,
        final Set<MavenElisionService.ArtifactSnapshot> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
        final Set<ArtifactCoordinate> reachableArtifacts) {
      for (final String rawRoot : roots) {
        final String root = rawRoot.replace('/', '.');
        for (final TierContext context : contexts) {
          final MavenElisionService.ArtifactSnapshot owner = context.ownerOf(root);
          addOwnedRoot(owner, root, candidates, candidateRoots, reachableArtifacts);
        }
      }
    }

    private void addOwnedRoot(
        final MavenElisionService.ArtifactSnapshot owner,
        final String root,
        final Set<MavenElisionService.ArtifactSnapshot> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
        final Set<ArtifactCoordinate> reachableArtifacts) {
      if (owner == null) {
        return;
      }
      if (!request.retainedCoordinates().contains(owner.coordinate())) {
        reachableArtifacts.add(owner.coordinate());
      }
      if (request.retainedCoordinates().contains(owner.coordinate())
          && candidates.contains(owner)) {
        candidateRoots.get(owner).add(root);
      }
    }

    private void addRequestedRoots(
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> requested,
        final List<TierContext> contexts,
        final Set<MavenElisionService.ArtifactSnapshot> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots)
        throws IOException {
      for (final Map.Entry<MavenElisionService.ArtifactSnapshot, Set<String>> entry :
          requested.entrySet()) {
        final Set<String> matching =
            rootsPresentInAnyTier(entry.getKey(), entry.getValue(), contexts);
        if (matching.isEmpty()) {
          throw new IOException(
              "Previously discovered roots are absent from every analyzed tier: "
                  + entry.getKey().coordinate());
        }
        if (candidates.contains(entry.getKey())) {
          candidateRoots.get(entry.getKey()).addAll(matching);
        }
      }
    }

    private static Set<String> rootsPresentInAnyTier(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Set<String> roots,
        final List<TierContext> contexts) {
      final Set<String> matching = new HashSet<>();
      for (final TierContext context : contexts) {
        matching.addAll(context.classesOf(snapshot));
      }
      matching.retainAll(roots);
      return matching;
    }

    private void addDynamicRoots(
        final List<MavenElisionService.ArtifactSnapshot> retainedLibraries,
        final List<TierContext> contexts,
        final Set<MavenElisionService.ArtifactSnapshot> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
        final Set<ArtifactCoordinate> reachableArtifacts,
        final Set<String> platformNames)
        throws IOException {
      for (final MavenElisionService.ArtifactSnapshot source : retainedLibraries) {
        for (final String root : MavenDependencyTrimmer.dynamicRoots(request, source.filePath())) {
          addDynamicRoot(
              root, contexts, candidates, candidateRoots, reachableArtifacts, platformNames);
        }
      }
    }

    private void addDynamicRoot(
        final String root,
        final List<TierContext> contexts,
        final Set<MavenElisionService.ArtifactSnapshot> candidates,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
        final Set<ArtifactCoordinate> reachableArtifacts,
        final Set<String> platformNames) {
      boolean found = false;
      for (final TierContext context : contexts) {
        final MavenElisionService.ArtifactSnapshot owner = context.ownerOf(root);
        if (owner == null) {
          continue;
        }
        found = true;
        addOwnedRoot(owner, root, candidates, candidateRoots, reachableArtifacts);
      }
      if (!found
          && !request.projectOutputClasses().contains(root)
          && !platformNames.contains(root)) {
        request.candidates().stream()
            .map(MavenElisionService.ArtifactSnapshot::coordinate)
            .filter(coordinate -> !request.retainedCoordinates().contains(coordinate))
            .forEach(reachableArtifacts::add);
      }
    }
  }

  /** Materializes target candidate inventories after roots have been resolved. */
  private final class CandidatePlanner {
    /** Shares the target tier and output context with the root plan. */
    private CandidatePlanner() {}

    private Map<MavenElisionService.ArtifactSnapshot, TierCandidate> createCandidates(
        final RootPlan rootPlan,
        final List<TierContext> projections,
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease)
        throws IOException {
      final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates =
          new LinkedHashMap<>();
      final Set<Path> outputPaths = new HashSet<>();
      for (final MavenElisionService.ArtifactSnapshot snapshot : rootPlan.candidateSnapshots()) {
        addCandidate(
            snapshot, rootPlan.roots(), projections, multiRelease, outputPaths, candidates);
      }
      return candidates;
    }

    private void addCandidate(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final Map<MavenElisionService.ArtifactSnapshot, Set<String>> candidateRoots,
        final List<TierContext> projections,
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiRelease,
        final Set<Path> outputPaths,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates)
        throws IOException {
      final Set<String> targetClasses = classesInTargetTier(snapshot, projections);
      final Path output =
          MavenDependencyTrimmer.outputPath(request.project(), snapshot.coordinate());
      if (!outputPaths.add(output)) {
        throw new IOException("Distinct tiered candidates share output path: " + output);
      }
      final MultiReleaseCandidateInfo mrInfo = multiRelease.get(snapshot);
      final Set<String> roots = new TreeSet<>(candidateRoots.get(snapshot));
      if (roots.isEmpty() && !targetClasses.isEmpty()) {
        roots.addAll(targetClasses);
      }
      candidates.put(snapshot, new TierCandidate(targetClasses, roots, mrInfo != null));
    }
  }

  /** Prepares candidate and program analyses against each tier's siblings. */
  private final class AnalysisPreparer {
    /** Prepares independent ProGuard contexts for each tier. */
    private AnalysisPreparer() {}

    private List<TierContext> prepareContexts(
        final Inventory inventory,
        final List<TierContext> projections,
        final RootPlan roots,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates)
        throws IOException {
      final Set<String> skipped = skippedIdentities(inventory.passThrough());
      final Set<String> unchangedClasses = unchangedPassThroughClasses(projections, skipped);
      final List<MavenElisionService.ArtifactSnapshot> unchangedPrograms =
          inventory.passThrough().retainedLibraries().stream()
              .filter(snapshot -> !roots.candidateSet().contains(snapshot))
              .toList();
      final List<TierContext> contexts = new ArrayList<>();
      final DependencyJarTrimmer trimmer = new DependencyJarTrimmer();
      for (final TierContext projection : projections) {
        contexts.add(
            prepareContext(
                projection,
                inventory,
                roots.candidateSnapshots(),
                unchangedPrograms,
                candidates,
                skipped,
                unchangedClasses,
                trimmer));
      }
      return List.copyOf(contexts);
    }

    private Set<String> skippedIdentities(final PassThroughPlan plan) {
      final Set<String> skipped = new LinkedHashSet<>(plan.skippedArtifactIdentities());
      forcedUnchanged.forEach(
          coordinate -> skipped.add(MavenDependencyTrimmer.artifactIdentity(coordinate)));
      return skipped;
    }

    private Set<String> unchangedPassThroughClasses(
        final List<TierContext> projections, final Set<String> skippedIdentities) {
      final Set<String> classes = new LinkedHashSet<>();
      for (final TierContext projection : projections) {
        for (final MavenElisionService.ArtifactSnapshot snapshot : request.candidates()) {
          if (skippedIdentities.contains(
              MavenDependencyTrimmer.artifactIdentity(snapshot.coordinate()))) {
            classes.addAll(projection.classesOf(snapshot));
          }
        }
      }
      return classes;
    }

    private TierContext prepareContext(
        final TierContext projection,
        final Inventory inventory,
        final List<MavenElisionService.ArtifactSnapshot> candidateSnapshots,
        final List<MavenElisionService.ArtifactSnapshot> unchangedPrograms,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final Set<String> skippedIdentities,
        final Set<String> unchangedClasses,
        final DependencyJarTrimmer trimmer)
        throws IOException {
      final TrimAnalysisSession session = new TrimAnalysisSession(trimmer);
      final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          candidatePrepared =
              prepareCandidateAnalyses(
                  projection,
                  inventory.snapshots(),
                  candidateSnapshots,
                  candidates,
                  unchangedClasses,
                  session);
      final Set<MavenElisionService.ArtifactSnapshot> programSnapshots =
          programSnapshots(projection.release(), candidateSnapshots, unchangedPrograms, candidates);
      final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          programPrepared =
              prepareProgramAnalyses(
                  projection,
                  inventory.snapshots(),
                  programSnapshots,
                  skippedIdentities,
                  unchangedClasses,
                  session);
      return projection.withPrepared(candidatePrepared, programPrepared);
    }

    private Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        prepareCandidateAnalyses(
            final TierContext projection,
            final List<MavenElisionService.ArtifactSnapshot> inventory,
            final List<MavenElisionService.ArtifactSnapshot> candidateSnapshots,
            final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
            final Set<String> unchangedClasses,
            final TrimAnalysisSession session)
            throws IOException {
      final List<MavenElisionService.ArtifactSnapshot> preparable =
          candidateSnapshots.stream()
              .filter(
                  snapshot ->
                      !(candidates.get(snapshot).isMultiRelease()
                          && projection.release() > targetRelease))
              .filter(snapshot -> !projection.classesOf(snapshot).isEmpty())
              .sorted(MavenDependencyTrimmer.artifactSnapshotOrder())
              .toList();
      final List<DependencyJarTrimmer.PreparedAnalysis> results =
          MavenDependencyTrimmer.mapParallel(
              preparable,
              request.trimWorkers(),
              snapshot -> {
                final List<Path> siblings = tierSiblings(inventory, projection, snapshot);
                return session.prepareWithUnchangedPassThroughLibraries(
                    projection.pathFor(snapshot),
                    siblings,
                    projection.platform(),
                    unchangedClasses);
              });
      final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          prepared = new LinkedHashMap<>();
      for (int index = 0; index < preparable.size(); index++) {
        prepared.put(preparable.get(index), results.get(index));
      }
      return prepared;
    }

    private Set<MavenElisionService.ArtifactSnapshot> programSnapshots(
        final int release,
        final List<MavenElisionService.ArtifactSnapshot> candidateSnapshots,
        final List<MavenElisionService.ArtifactSnapshot> unchangedPrograms,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates) {
      final Set<MavenElisionService.ArtifactSnapshot> programs =
          new LinkedHashSet<>(unchangedPrograms);
      if (release > targetRelease) {
        candidateSnapshots.stream()
            .filter(snapshot -> candidates.get(snapshot).isMultiRelease())
            .forEach(programs::add);
      }
      return programs;
    }

    private Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
        prepareProgramAnalyses(
            final TierContext projection,
            final List<MavenElisionService.ArtifactSnapshot> inventory,
            final Set<MavenElisionService.ArtifactSnapshot> programs,
            final Set<String> skippedIdentities,
            final Set<String> unchangedClasses,
            final TrimAnalysisSession session)
            throws IOException {
      final List<MavenElisionService.ArtifactSnapshot> preparable =
          programs.stream()
              .filter(snapshot -> !projection.classesOf(snapshot).isEmpty())
              .sorted(MavenDependencyTrimmer.artifactSnapshotOrder())
              .toList();
      final List<DependencyJarTrimmer.PreparedAnalysis> results =
          MavenDependencyTrimmer.mapParallel(
              preparable,
              request.trimWorkers(),
              snapshot ->
                  prepareProgram(
                      snapshot, projection, inventory, skippedIdentities, unchangedClasses, session));
      final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          prepared = new LinkedHashMap<>();
      for (int index = 0; index < preparable.size(); index++) {
        prepared.put(preparable.get(index), results.get(index));
      }
      return prepared;
    }

    private DependencyJarTrimmer.PreparedAnalysis prepareProgram(
        final MavenElisionService.ArtifactSnapshot snapshot,
        final TierContext projection,
        final List<MavenElisionService.ArtifactSnapshot> inventory,
        final Set<String> skippedIdentities,
        final Set<String> unchangedClasses,
        final TrimAnalysisSession session)
        throws IOException {
      final List<Path> siblings = tierSiblings(inventory, projection, snapshot);
      final Path programPath = projection.pathFor(snapshot);
      if (skippedIdentities.contains(
          MavenDependencyTrimmer.artifactIdentity(snapshot.coordinate()))) {
        return session.prepareUnchangedPassThrough(
            programPath, siblings, projection.platform(), unchangedClasses);
      }
      return session.prepareWithUnchangedPassThroughLibraries(
          programPath, siblings, projection.platform(), unchangedClasses);
    }
  }

  /** Extends roots to a fixed point and produces the target-tier analyses. */
  private final class ClosureAnalyzer {
    /** Runs the monotonic root closure and assembles target analyses. */
    private ClosureAnalyzer() {}

    private ClosureResult analyzeToFixedPoint(
        final List<TierContext> contexts,
        final RootPlan roots,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates)
        throws IOException {
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses =
          new LinkedHashMap<>();
      int analysisRuns = 0;
      boolean changed;
      do {
        final ClosureIteration iteration =
            analyzeIteration(contexts, roots, candidates, targetAnalyses);
        changed = iteration.rootsChanged();
        analysisRuns += iteration.analysisRuns();
      } while (changed);
      return new ClosureResult(targetAnalyses, roots.reachableArtifacts(), analysisRuns);
    }

    private ClosureIteration analyzeIteration(
        final List<TierContext> contexts,
        final RootPlan roots,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses)
        throws IOException {
      boolean changed = false;
      int runs = 0;
      for (final TierContext context : contexts) {
        final ClosureIteration programs = analyzePrograms(context, candidates, roots);
        changed |= programs.rootsChanged();
        runs += programs.analysisRuns();
        final ClosureIteration candidateResults =
            analyzeCandidates(context, candidates, roots, targetAnalyses);
        changed |= candidateResults.rootsChanged();
        runs += candidateResults.analysisRuns();
      }
      return new ClosureIteration(changed, runs);
    }

    private ClosureIteration analyzePrograms(
        final TierContext context,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final RootPlan roots)
        throws IOException {
      boolean changed = false;
      final List<
              Map.Entry<
                  MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          entries =
              context.programEntries().stream()
                  .filter(
                      entry ->
                          !rootsForProgram(
                                  context, entry.getKey(), candidates.get(entry.getKey()))
                              .isEmpty())
                  .toList();
      final List<DependencyJarTrimmer.TrimAnalysis> analyses =
          MavenDependencyTrimmer.mapParallel(
              entries,
              request.trimWorkers(),
              entry ->
                  entry
                      .getValue()
                      .analyze(
                          rootsForProgram(context, entry.getKey(), candidates.get(entry.getKey()))));
      for (int index = 0; index < entries.size(); index++) {
        final Map.Entry<
                MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            entry = entries.get(index);
        final MavenElisionService.ArtifactSnapshot owner = entry.getKey();
        final TierCandidate candidate = candidates.get(owner);
        final DependencyJarTrimmer.TrimAnalysis analysis = analyses.get(index);
        if (candidate != null && candidate.isMultiRelease() && context.release() > targetRelease) {
          changed |= retainSameJarTargetClasses(candidate, analysis, context.classesOf(owner));
        }
        changed |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(), owner, context, candidates, roots);
      }
      return new ClosureIteration(changed, analyses.size());
    }

    private Set<String> rootsForProgram(
        final TierContext context,
        final MavenElisionService.ArtifactSnapshot owner,
        final TierCandidate candidate) {
      if (candidate == null || context.release() <= targetRelease) {
        return context.classesOf(owner);
      }
      final MultiReleaseCandidateInfo info = context.multiReleaseInfo(owner);
      if (info == null) {
        return Set.of();
      }
      final Set<String> roots = new TreeSet<>(info.versionedClasses());
      roots.retainAll(context.classesOf(owner));
      return roots;
    }

    private static boolean retainSameJarTargetClasses(
        final TierCandidate candidate,
        final DependencyJarTrimmer.TrimAnalysis analysis,
        final Set<String> tierClasses) {
      boolean changed = false;
      for (final String retained : analysis.retainedClasses()) {
        final String dotted = retained.replace('/', '.');
        if (tierClasses.contains(dotted)) {
          changed |= candidate.roots().add(dotted);
        }
      }
      return changed;
    }

    private ClosureIteration analyzeCandidates(
        final TierContext context,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final RootPlan roots,
        final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses)
        throws IOException {
      boolean changed = false;
      final List<
              Map.Entry<
                  MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
          entries = context.candidateEntries();
      final List<DependencyJarTrimmer.TrimAnalysis> analyses =
          MavenDependencyTrimmer.mapParallel(
              entries,
              request.trimWorkers(),
              entry -> {
                final TierCandidate candidate = candidates.get(entry.getKey());
                final Set<String> localRoots =
                    candidate.localRoots(context.classesOf(entry.getKey()));
                return candidateAnalysis(candidate, localRoots, entry.getValue());
              });
      for (int index = 0; index < entries.size(); index++) {
        final Map.Entry<
                MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            entry = entries.get(index);
        final MavenElisionService.ArtifactSnapshot snapshot = entry.getKey();
        final TierCandidate candidate = candidates.get(snapshot);
        final DependencyJarTrimmer.TrimAnalysis analysis = analyses.get(index);
        if (context.release() == targetRelease) {
          targetAnalyses.put(snapshot.coordinate(), analysis);
        }
        changed |=
            collectReachableClasses(
                analysis.reachableLibraryClasses(), snapshot, context, candidates, roots);
      }
      return new ClosureIteration(changed, analyses.size());
    }

    private static DependencyJarTrimmer.TrimAnalysis candidateAnalysis(
        final TierCandidate candidate,
        final Set<String> localRoots,
        final DependencyJarTrimmer.PreparedAnalysis prepared)
        throws IOException {
      if (candidate.isMultiRelease() && localRoots.isEmpty() && !candidate.roots().isEmpty()) {
        return new DependencyJarTrimmer.TrimAnalysis(
            candidate.classes().size(), Set.of(), Set.of(), Set.of());
      }
      return prepared.analyze(localRoots);
    }

    private boolean collectReachableClasses(
        final Set<String> reachable,
        final MavenElisionService.ArtifactSnapshot source,
        final TierContext context,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final RootPlan roots) {
      boolean changed = false;
      for (final String name : reachable) {
        final String dotted = name.replace('/', '.');
        final MavenElisionService.ArtifactSnapshot owner = context.ownerOf(dotted);
        if (owner == null || owner.equals(source)) {
          continue;
        }
        final TierCandidate candidate = candidates.get(owner);
        if (candidate != null) {
          changed |= candidate.roots().add(dotted);
        } else if (!request.retainedCoordinates().contains(owner.coordinate())) {
          roots.reachableArtifacts().add(owner.coordinate());
        }
      }
      return changed;
    }

    private InMemoryAnalysis createResult(
        final Inventory inventory,
        final RootPlan roots,
        final Map<MavenElisionService.ArtifactSnapshot, TierCandidate> candidates,
        final ClosureResult closure)
        throws IOException {
      final Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> analyses =
          new LinkedHashMap<>(closure.targetAnalyses());
      for (final MavenElisionService.ArtifactSnapshot snapshot : roots.candidateSnapshots()) {
        analyses.computeIfAbsent(snapshot.coordinate(), ignored -> EMPTY_ANALYSIS);
      }
      final Map<ArtifactCoordinate, Set<String>> upperClasses = new LinkedHashMap<>();
      final Map<MavenElisionService.ArtifactSnapshot, Set<String>> rootMap = new LinkedHashMap<>();
      for (final Map.Entry<MavenElisionService.ArtifactSnapshot, TierCandidate> entry :
          candidates.entrySet()) {
        final TierCandidate candidate = entry.getValue();
        rootMap.put(entry.getKey(), candidate.roots());
        if (candidate.isMultiRelease()) {
          final Set<String> upper = classNamesAboveRelease(entry.getKey());
          upperClasses.put(entry.getKey().coordinate(), upper);
        }
      }
      return MavenDependencyTrimmer.inMemoryResult(
          analyses,
          rootMap,
          closure.reachableArtifacts(),
          closure.analysisRuns(),
          targetRelease,
          runtimeRelease,
          javaHome,
          inventory.platformSnapshots(),
          upperClasses);
    }

    private Set<String> classNamesAboveRelease(final MavenElisionService.ArtifactSnapshot snapshot)
        throws IOException {
      return MultiReleaseClassInventory.classNamesAboveRelease(snapshot.filePath(), targetRelease);
    }
  }

  private record Inventory(
      List<MavenElisionService.ArtifactSnapshot> snapshots,
      PassThroughPlan passThrough,
      Path projectionDirectory,
      Map<Path, Set<String>> classesBySourcePath,
      Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiReleaseCandidates,
      List<Integer> tiers,
      List<JdkPlatformContext.PlatformSnapshot> platformSnapshots) {
    private Inventory(
        final List<MavenElisionService.ArtifactSnapshot> snapshots,
        final PassThroughPlan passThrough,
        final Path projectionDirectory,
        final Map<Path, Set<String>> classesBySourcePath,
        final Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo>
            multiReleaseCandidates,
        final List<Integer> tiers) {
      this(
          List.copyOf(snapshots),
          passThrough,
          projectionDirectory,
          Map.copyOf(classesBySourcePath),
          Map.copyOf(multiReleaseCandidates),
          List.copyOf(tiers),
          List.of());
    }

    private Inventory withPlatformSnapshots(
        final List<JdkPlatformContext.PlatformSnapshot> snapshots) {
      return new Inventory(
          this.snapshots,
          passThrough,
          projectionDirectory,
          classesBySourcePath,
          multiReleaseCandidates,
          tiers,
          List.copyOf(snapshots));
    }
  }

  private record PlatformPlan(
      List<JdkPlatformContext.PlatformSnapshot> snapshots, Map<Integer, ClassPool> byRelease) {}

  private record RootPlan(
      List<MavenElisionService.ArtifactSnapshot> candidateSnapshots,
      Set<MavenElisionService.ArtifactSnapshot> candidateSet,
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> roots,
      Set<ArtifactCoordinate> reachableArtifacts) {}

  private record ClosureResult(
      Map<ArtifactCoordinate, DependencyJarTrimmer.TrimAnalysis> targetAnalyses,
      Set<ArtifactCoordinate> reachableArtifacts,
      int analysisRuns) {}

  private record ClosureIteration(boolean rootsChanged, int analysisRuns) {}

  private record MultiReleaseCandidateInfo(
      Set<String> requiredTargetRoots, Set<String> versionedClasses) {
    private MultiReleaseCandidateInfo {
      requiredTargetRoots = Set.copyOf(requiredTargetRoots);
      versionedClasses = Set.copyOf(versionedClasses);
    }
  }

  /** Candidate class inventory and the roots retained across tier analyses. */
  private record TierCandidate(
      Set<String> candidateClasses, Set<String> rootNames, boolean multiReleaseCandidate) {
    private TierCandidate {
      candidateClasses = Set.copyOf(candidateClasses);
      rootNames = new TreeSet<>(rootNames);
    }

    private Set<String> localRoots(final Set<String> classesInTier) {
      final Set<String> local = new TreeSet<>(rootNames);
      local.retainAll(classesInTier);
      return local;
    }

    private Set<String> roots() {
      return rootNames;
    }

    private Set<String> classes() {
      return candidateClasses;
    }

    private boolean isMultiRelease() {
      return multiReleaseCandidate;
    }
  }

  /** One runtime tier's classpath projection and prepared analyses. */
  private record TierContext(
      int tierRelease,
      int targetCompilerRelease,
      Map<MavenElisionService.ArtifactSnapshot, MultiReleaseCandidateInfo> multiReleaseCandidates,
      Map<MavenElisionService.ArtifactSnapshot, Path> paths,
      Map<MavenElisionService.ArtifactSnapshot, Set<String>> classes,
      Map<String, MavenElisionService.ArtifactSnapshot> ownerByClass,
      Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          candidatePrepared,
      Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
          programPrepared,
      ClassPool platformPool) {
    private TierContext {
      multiReleaseCandidates = Map.copyOf(multiReleaseCandidates);
      paths = Map.copyOf(paths);
      classes = Map.copyOf(classes);
      ownerByClass = Map.copyOf(ownerByClass);
      candidatePrepared = Map.copyOf(candidatePrepared);
      programPrepared = Map.copyOf(programPrepared);
    }

    private TierContext withPrepared(
        final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            candidates,
        final Map<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>
            programs) {
      return new TierContext(
          tierRelease,
          targetCompilerRelease,
          multiReleaseCandidates,
          paths,
          classes,
          ownerByClass,
          candidates,
          programs,
          platformPool);
    }

    private int release() {
      return tierRelease;
    }

    private int targetRelease() {
      return targetCompilerRelease;
    }

    private Path pathFor(final MavenElisionService.ArtifactSnapshot snapshot) {
      return paths.get(snapshot);
    }

    private Set<String> classesOf(final MavenElisionService.ArtifactSnapshot snapshot) {
      return classes.getOrDefault(snapshot, Set.of());
    }

    private MavenElisionService.ArtifactSnapshot ownerOf(final String name) {
      return ownerByClass.get(name);
    }

    private ClassPool platform() {
      return platformPool;
    }

    private List<
            Map.Entry<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        candidateEntries() {
      return List.copyOf(candidatePrepared.entrySet());
    }

    private List<
            Map.Entry<MavenElisionService.ArtifactSnapshot, DependencyJarTrimmer.PreparedAnalysis>>
        programEntries() {
      return List.copyOf(programPrepared.entrySet());
    }

    private MultiReleaseCandidateInfo multiReleaseInfo(
        final MavenElisionService.ArtifactSnapshot snapshot) {
      return multiReleaseCandidates.get(snapshot);
    }
  }
}
