/* WHY: Separates ProGuard linking and edge indexing from archive pool construction. */

package io.github.spockz.elider.trimmer;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.util.InvalidReferenceVisitor;

/** WHY: One indexer owns candidate precedence, typed edges, and graph diagnostics. */
@SuppressWarnings({
  "PMD.TooManyMethods",
  "PMD.UseConcurrentHashMap",
  "PMD.CompareObjectsWithEquals",
  "PMD.CommentDefaultAccessModifier"
})
final class ReferenceGraphIndexer {
  /** Program pool keeps candidate class resolution ahead of sibling libraries. */
  private final ClassPool programPool;

  /** Ordered siblings and platform fallback classes have library roles. */
  private final ClassPool libraryPool;

  /** Platform entries resolve references but do not enter candidate closure. */
  private final Set<String> platformNames;

  /** Owning archive snapshots supply cached per-class reference evidence. */
  private final Map<String, ArchiveSnapshot> archiveByClass;

  /** Captures the isolated pools whose classes define the graph context. */
  ReferenceGraphIndexer(
      final ClassPool programPool, final ClassPool libraryPool, final Set<String> platformNames) {
    this(programPool, libraryPool, platformNames, Map.of());
  }

  ReferenceGraphIndexer(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformNames,
      final Map<String, ArchiveSnapshot> archiveByClass) {
    this.programPool = programPool;
    this.libraryPool = libraryPool;
    this.platformNames = platformNames;
    this.archiveByClass = archiveByClass;
  }

  /** Initializes references and freezes the resulting graph. */
  ReferenceGraph build() {
    final Function<String, Clazz> lookup = classLookup(programPool, libraryPool);
    final Map<String, RuntimeException> edgeFailures = new HashMap<>();
    final Map<String, Set<String>> signatureTypes = new HashMap<>();
    final SignaturePolymorphicReferenceResolver signatureResolver =
        new SignaturePolymorphicReferenceResolver(signatureTypes, lookup);
    final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries = new HashMap<>();
    final InvalidReferenceVisitor libraryInvalidVisitor =
        ProGuardReferenceVisitors.recordingLibraryInvalid(unresolvedLibraries, signatureResolver);
    ProGuardReferenceInitialization.libraries(
        programPool, libraryPool, platformNames, libraryInvalidVisitor, edgeFailures);
    final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms = new HashMap<>();
    final InvalidReferenceVisitor programInvalidVisitor =
        ProGuardReferenceVisitors.recordingInvalid(unresolvedPrograms, signatureResolver);
    ProGuardReferenceInitialization.program(
        programPool, libraryPool, programInvalidVisitor, edgeFailures);
    return graph(
        programPool,
        libraryPool,
        platformNames,
        lookup,
        signatureResolver,
        unresolvedPrograms,
        unresolvedLibraries,
        archiveByClass,
        edgeFailures);
  }

  /** Initializes and freezes only the shared library tier graph for reuse. */
  ReferenceGraph buildLibraryTier() {
    final Function<String, Clazz> lookup = classLookup(programPool, libraryPool);
    final Map<String, RuntimeException> edgeFailures = new HashMap<>();
    final Map<String, Set<String>> signatureTypes = new HashMap<>();
    final SignaturePolymorphicReferenceResolver signatureResolver =
        new SignaturePolymorphicReferenceResolver(signatureTypes, lookup);
    final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries = new HashMap<>();
    final InvalidReferenceVisitor libraryInvalidVisitor =
        ProGuardReferenceVisitors.recordingLibraryInvalid(unresolvedLibraries, signatureResolver);
    ProGuardReferenceInitialization.libraries(
        programPool, libraryPool, platformNames, libraryInvalidVisitor, edgeFailures);
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges = new HashMap<>();
    final Map<String, Set<String>> unrecognizedAttributes = new HashMap<>();
    collectTypedEvidence(
        archiveByClass, programPool, typedEdges, unrecognizedAttributes, edgeFailures);
    final EdgeCollector collector = new EdgeCollector(programPool, libraryPool, platformNames);
    final Map<String, Set<String>> classConstantTargets = new HashMap<>();
    final Map<String, Set<String>> nonPoolTargets = new HashMap<>();
    for (final Clazz clazz : libraryPool.classes()) {
      if (!platformNames.contains(clazz.getName())) {
        collectEdges(
            clazz,
            lookup,
            signatureResolver,
            collector,
            edges,
            classConstantTargets,
            nonPoolTargets,
            edgeFailures);
      }
    }
    final Predicate<String> targetExists =
        targetExistsLookup(programPool, libraryPool, archiveByClass);
    recordMissingTypedTargets(
        programPool, targetExists, typedEdges, new HashMap<>(), unresolvedLibraries);
    mergeTypedEdges(edges, typedEdges);
    final Map<String, Set<String>> unusedConstantPoolEdges =
        unusedConstantPoolEdges(
            classConstantTargets, nonPoolTargets, typedEdges, unrecognizedAttributes);
    final Map<String, Set<String>> unclassifiedEdges =
        unclassifiedEdges(edges, typedEdges, unusedConstantPoolEdges);
    return new ReferenceGraph(
        Set.of(),
        classNames(libraryPool, platformNames),
        wrapUnmodifiableSets(edges),
        Collections.unmodifiableMap(typedEdges),
        wrapUnmodifiableSets(unclassifiedEdges),
        wrapUnmodifiableSets(unusedConstantPoolEdges),
        wrapUnmodifiableSets(unrecognizedAttributes),
        Map.of(),
        wrapUnmodifiableSets(unresolvedLibraries),
        Collections.unmodifiableMap(edgeFailures),
        0);
  }

  /** Indexes candidate program classes and overlays them onto a shared tier. */
  ReferenceGraph buildProgramWithSharedTier(final TierLibraryIndex libraryIndex) {
    final Function<String, Clazz> lookup = classLookup(programPool, libraryPool);
    final Map<String, RuntimeException> edgeFailures = new HashMap<>();
    final Map<String, Set<String>> signatureTypes = new HashMap<>();
    final SignaturePolymorphicReferenceResolver signatureResolver =
        new SignaturePolymorphicReferenceResolver(signatureTypes, lookup);
    final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms = new HashMap<>();
    final InvalidReferenceVisitor programInvalidVisitor =
        ProGuardReferenceVisitors.recordingInvalid(unresolvedPrograms, signatureResolver);
    ProGuardReferenceInitialization.program(
        programPool, libraryPool, programInvalidVisitor, edgeFailures);
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges = new HashMap<>();
    final Map<String, Set<String>> unrecognizedAttributes = new HashMap<>();
    collectTypedEvidence(
        archiveByClass, programPool, typedEdges, unrecognizedAttributes, edgeFailures);
    final EdgeCollector collector = new EdgeCollector(programPool, libraryPool, platformNames);
    final Map<String, Set<String>> classConstantTargets = new HashMap<>();
    final Map<String, Set<String>> nonPoolTargets = new HashMap<>();
    for (final Clazz clazz : programPool.classes()) {
      collectEdges(
          clazz,
          lookup,
          signatureResolver,
          collector,
          edges,
          classConstantTargets,
          nonPoolTargets,
          edgeFailures);
    }
    final Predicate<String> targetExists =
        targetExistsLookup(programPool, libraryPool, archiveByClass, libraryIndex);
    recordMissingTypedTargets(
        programPool, targetExists, typedEdges, unresolvedPrograms, new HashMap<>());
    mergeTypedEdges(edges, typedEdges);
    final Map<String, Set<String>> unusedConstantPoolEdges =
        unusedConstantPoolEdges(
            classConstantTargets, nonPoolTargets, typedEdges, unrecognizedAttributes);
    final Map<String, Set<String>> unclassifiedEdges =
        unclassifiedEdges(edges, typedEdges, unusedConstantPoolEdges);
    final ReferenceGraph programGraph =
        new ReferenceGraph(
            classNames(programPool),
            Set.of(),
            wrapUnmodifiableSets(edges),
            Collections.unmodifiableMap(typedEdges),
            wrapUnmodifiableSets(unclassifiedEdges),
            wrapUnmodifiableSets(unusedConstantPoolEdges),
            wrapUnmodifiableSets(unrecognizedAttributes),
            wrapUnmodifiableSets(unresolvedPrograms),
            Map.of(),
            Collections.unmodifiableMap(edgeFailures),
            programPool.size());
    return libraryIndex.overlayWithProgram(programGraph);
  }

  private static Function<String, Clazz> classLookup(
      final ClassPool programPool, final ClassPool libraryPool) {
    return name -> {
      final Clazz programClass = programPool.getClass(name);
      return programClass == null ? libraryPool.getClass(name) : programClass;
    };
  }

  private static Predicate<String> targetExistsLookup(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Map<String, ArchiveSnapshot> archiveByClass) {
    return targetExistsLookup(programPool, libraryPool, archiveByClass, null);
  }

  private static Predicate<String> targetExistsLookup(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Map<String, ArchiveSnapshot> archiveByClass,
      final TierLibraryIndex libraryIndex) {
    final Set<String> verifiedPresent = new HashSet<>();
    return target -> {
      if (verifiedPresent.contains(target)) {
        return true;
      }
      final boolean exists =
          (libraryIndex != null && libraryIndex.containsClass(target))
              || archiveByClass.containsKey(target)
              || programPool.getClass(target) != null
              || (libraryPool instanceof LazyPlatformClassPool lazyPool
                  ? lazyPool.hasClass(target)
                  : libraryPool.getClass(target) != null);
      if (exists) {
        verifiedPresent.add(target);
      }
      return exists;
    };
  }

  // WHY: ASM reports malformed class records through unchecked failures.
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void collectTypedEvidence(
      final Map<String, ArchiveSnapshot> archiveByClass,
      final ClassPool programPool,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, Set<String>> unrecognizedAttributes,
      final Map<String, RuntimeException> edgeFailures) {
    archiveByClass.forEach(
        (name, archive) -> {
          try {
            final ClassReferenceEvidence.Result result =
                archive.referenceEvidence(name, programPool.getClass(name) != null);
            typedEdges.put(name, result.references());
            if (!result.unrecognizedAttributes().isEmpty()) {
              unrecognizedAttributes.put(name, result.unrecognizedAttributes());
            }
          } catch (final RuntimeException exception) {
            edgeFailures.put(name, classificationFailure(name, exception));
          }
        });
  }

  private static void mergeTypedEdges(
      final Map<String, Set<String>> edges,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges) {
    typedEdges.forEach(
        (source, targets) ->
            edges.computeIfAbsent(source, ignored -> new HashSet<>()).addAll(targets.keySet()));
  }

  static IllegalArgumentException classificationFailure(
      final String className, final RuntimeException cause) {
    return new IllegalArgumentException(
        "Could not classify unclassified reference evidence for class " + className, cause);
  }

  private static ReferenceGraph graph(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformClasses,
      final Function<String, Clazz> classLookup,
      final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries,
      final Map<String, ArchiveSnapshot> archiveByClass,
      final Map<String, RuntimeException> edgeFailures) {
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges = new HashMap<>();
    final Map<String, Set<String>> unrecognizedAttributes = new HashMap<>();
    collectTypedEvidence(
        archiveByClass, programPool, typedEdges, unrecognizedAttributes, edgeFailures);
    final EdgeCollector collector = new EdgeCollector(programPool, libraryPool, platformClasses);
    final Map<String, Set<String>> classConstantTargets = new HashMap<>();
    final Map<String, Set<String>> nonPoolTargets = new HashMap<>();
    for (final Clazz clazz : programPool.classes()) {
      collectEdges(
          clazz,
          classLookup,
          signaturePolymorphicResolver,
          collector,
          edges,
          classConstantTargets,
          nonPoolTargets,
          edgeFailures);
    }
    for (final Clazz clazz : libraryPool.classes()) {
      if (!platformClasses.contains(clazz.getName())) {
        collectEdges(
            clazz,
            classLookup,
            signaturePolymorphicResolver,
            collector,
            edges,
            classConstantTargets,
            nonPoolTargets,
            edgeFailures);
      }
    }
    final Predicate<String> targetExists =
        targetExistsLookup(programPool, libraryPool, archiveByClass);
    recordMissingTypedTargets(
        programPool, targetExists, typedEdges, unresolvedPrograms, unresolvedLibraries);
    mergeTypedEdges(edges, typedEdges);
    final Map<String, Set<String>> unusedConstantPoolEdges =
        unusedConstantPoolEdges(
            classConstantTargets, nonPoolTargets, typedEdges, unrecognizedAttributes);
    final Map<String, Set<String>> unclassifiedEdges =
        unclassifiedEdges(edges, typedEdges, unusedConstantPoolEdges);
    return new ReferenceGraph(
        classNames(programPool),
        classNames(libraryPool, platformClasses),
        wrapUnmodifiableSets(edges),
        Collections.unmodifiableMap(typedEdges),
        wrapUnmodifiableSets(unclassifiedEdges),
        wrapUnmodifiableSets(unusedConstantPoolEdges),
        wrapUnmodifiableSets(unrecognizedAttributes),
        wrapUnmodifiableSets(unresolvedPrograms),
        wrapUnmodifiableSets(unresolvedLibraries),
        Collections.unmodifiableMap(edgeFailures),
        programPool.size());
  }

  private static void recordMissingTypedTargets(
      final ClassPool programPool,
      final Predicate<String> targetExists,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries) {
    typedEdges.forEach(
        (source, targets) -> {
          final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolved =
              programPool.getClass(source) == null ? unresolvedLibraries : unresolvedPrograms;
          targets.forEach(
              (target, kinds) -> {
                if (!targetExists.test(target)) {
                  final String evidence =
                      kinds.contains(ReferenceGraph.EdgeKind.STRUCTURAL)
                          ? "structural"
                          : kinds.contains(ReferenceGraph.EdgeKind.BODY)
                              ? "body"
                              : "debug metadata";
                  unresolved
                      .computeIfAbsent(source, unused -> new LinkedHashSet<>())
                      .add(
                          new ReferenceGraph.UnresolvedLink(
                              target,
                              ReferenceGraph.UnresolvedKind.MISSING_CLASS,
                              source + " -> unresolved " + evidence + " class " + target));
                }
              });
        });
  }

  private static Map<String, Set<String>> unclassifiedEdges(
      final Map<String, Set<String>> completeEdges,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, Set<String>> unusedConstantPoolEdges) {
    final Map<String, Set<String>> unclassifiedBySource = new HashMap<>();
    completeEdges.forEach(
        (source, targets) -> {
          final Set<String> typedTargets = typedEdges.getOrDefault(source, Map.of()).keySet();
          final Set<String> unusedTargets = unusedConstantPoolEdges.getOrDefault(source, Set.of());
          Set<String> unclassified = null;
          for (final String target : targets) {
            if (!typedTargets.contains(target) && !unusedTargets.contains(target)) {
              unclassified = addMissing(unclassified, target);
            }
          }
          if (unclassified != null) {
            unclassifiedBySource.put(source, unclassified);
          }
        });
    return unclassifiedBySource;
  }

  private static Set<String> addMissing(final Set<String> existing, final String target) {
    final Set<String> targetSet = existing == null ? new HashSet<>() : existing;
    targetSet.add(target);
    return targetSet;
  }

  private static Map<String, Set<String>> unusedConstantPoolEdges(
      final Map<String, Set<String>> classConstantTargets,
      final Map<String, Set<String>> nonPoolTargets,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, Set<String>> unrecognizedAttributes) {
    final Map<String, Set<String>> unusedBySource = new HashMap<>();
    classConstantTargets.forEach(
        (source, targets) -> {
          if (unrecognizedAttributes.containsKey(source)) {
            return;
          }
          final Set<String> nonPool = nonPoolTargets.getOrDefault(source, Set.of());
          final Set<String> typed = typedEdges.getOrDefault(source, Map.of()).keySet();
          Set<String> unused = null;
          for (final String target : targets) {
            if (!nonPool.contains(target) && !typed.contains(target)) {
              unused = addMissing(unused, target);
            }
          }
          if (unused != null) {
            unusedBySource.put(source, unused);
          }
        });
    return unusedBySource;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void collectEdges(
      final Clazz clazz,
      final Function<String, Clazz> classLookup,
      final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver,
      final EdgeCollector edgeCollector,
      final Map<String, Set<String>> edges,
      final Map<String, Set<String>> classConstantTargets,
      final Map<String, Set<String>> nonPoolTargets,
      final Map<String, RuntimeException> edgeFailures) {
    final Set<String> targets = new LinkedHashSet<>();
    edgeCollector.collectInto(targets);
    try {
      clazz.accept(ProGuardReferenceVisitors.complete(edgeCollector, classLookup));
      signaturePolymorphicResolver.enqueueDescriptorTypes(clazz, edgeCollector);
      // Eager indexing defers failures until the owning class enters the closure.
    } catch (final RuntimeException exception) {
      edgeFailures.putIfAbsent(clazz.getName(), classificationFailure(clazz.getName(), exception));
    }
    edges.put(clazz.getName(), targets);
    final Set<String> classConstants = edgeCollector.drainClassConstants();
    if (!classConstants.isEmpty()) {
      classConstantTargets.put(clazz.getName(), classConstants);
    }
    final Set<String> nonPool = edgeCollector.drainNonPoolTargets();
    if (!nonPool.isEmpty()) {
      nonPoolTargets.put(clazz.getName(), nonPool);
    }
  }

  private static Set<String> classNames(final ClassPool pool) {
    final Set<String> names = HashSet.newHashSet(pool.size());
    pool.classNames().forEachRemaining(names::add);
    return Collections.unmodifiableSet(names);
  }

  private static Set<String> classNames(final ClassPool pool, final Set<String> excludedNames) {
    final Set<String> names = HashSet.newHashSet(pool.size());
    pool.classNames()
        .forEachRemaining(
            name -> {
              if (!excludedNames.contains(name)) {
                names.add(name);
              }
            });
    return Collections.unmodifiableSet(names);
  }

  private static <T> Map<String, Set<T>> wrapUnmodifiableSets(final Map<String, Set<T>> source) {
    source.replaceAll((name, values) -> Set.copyOf(values));
    return Collections.unmodifiableMap(source);
  }

  /** Collects candidate and sibling nodes, excluding platform classes. */
  private static final class EdgeCollector
      implements ProGuardReferenceVisitors.OriginTrackingClassVisitor {
    /** Candidate pool establishes ProgramClass identity precedence. */
    private final ClassPool programPool;

    /** Library class table places siblings before active JDK fallbacks. */
    private final ClassPool libraryPool;

    /** Platform names are excluded from traversal and result accounting. */
    private final Set<String> platformLibraryClasses;

    /** Target set currently receiving ProGuard visitor callbacks. */
    private Set<String> currentEdges = Set.of();

    /** WHY: Preserves constant-pool origins for the current visitor callback target. */
    private Set<String> currentClassConstants = Set.of();

    /** WHY: Separates references outside the indexed candidate and sibling pools. */
    private Set<String> currentNonPoolTargets = Set.of();

    /** WHY: Restores nested ProGuard callback roles after each scoped visitor call. */
    private int currentOriginMask;

    private EdgeCollector(
        final ClassPool programPool,
        final ClassPool libraryPool,
        final Set<String> platformLibraryClasses) {
      this.programPool = programPool;
      this.libraryPool = libraryPool;
      this.platformLibraryClasses = platformLibraryClasses;
    }

    private void collectInto(final Set<String> edges) {
      currentEdges = edges;
      currentClassConstants = Set.of();
      currentNonPoolTargets = Set.of();
    }

    private Set<String> drainClassConstants() {
      final Set<String> drained = currentClassConstants;
      currentClassConstants = Set.of();
      return drained;
    }

    private Set<String> drainNonPoolTargets() {
      final Set<String> drained = currentNonPoolTargets;
      currentNonPoolTargets = Set.of();
      return drained;
    }

    private Set<String> classConstants() {
      if (currentClassConstants.isEmpty()) {
        currentClassConstants = new HashSet<>();
      }
      return currentClassConstants;
    }

    private Set<String> nonPoolTargets() {
      if (currentNonPoolTargets.isEmpty()) {
        currentNonPoolTargets = new HashSet<>();
      }
      return currentNonPoolTargets;
    }

    @Override
    @SuppressWarnings("PMD.UnusedAssignment")
    public void withOrigin(
        final ProGuardReferenceVisitors.EdgeOrigin origin, final Runnable action) {
      final int previous = currentOriginMask;
      currentOriginMask |= origin.mask;
      try {
        action.run();
      } finally {
        currentOriginMask = previous;
      }
    }

    @Override
    public void recordClassConstant(final String name) {
      final org.objectweb.asm.Type type =
          name.startsWith("[") ? org.objectweb.asm.Type.getType(name) : null;
      if (type == null) {
        classConstants().add(name);
      } else {
        final org.objectweb.asm.Type element = type.getElementType();
        if (element.getSort() == org.objectweb.asm.Type.OBJECT) {
          classConstants().add(element.getInternalName());
        }
      }
    }

    @Override
    public void visitAnyClass(final Clazz clazz) {
      if (programPool.getClass(clazz.getName()) == clazz
          || (libraryPool.getClass(clazz.getName()) == clazz
              && !platformLibraryClasses.contains(clazz.getName()))) {
        currentEdges.add(clazz.getName());
        if ((currentOriginMask & ProGuardReferenceVisitors.EdgeOrigin.CLASS_CONSTANT.mask) != 0) {
          classConstants().add(clazz.getName());
        }
        if ((currentOriginMask & ProGuardReferenceVisitors.EdgeOrigin.OTHER.mask) != 0) {
          nonPoolTargets().add(clazz.getName());
        }
      }
    }
  }
}
