/* WHY: Separates ProGuard linking and edge indexing from archive pool construction. */

package io.github.spockz.elider.trimmer;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.util.InvalidReferenceVisitor;
import proguard.classfile.visitor.ClassVisitor;

/** Initializes reference roles and freezes adjacency and unresolved-link evidence. */
@SuppressWarnings({
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

  /** Original class bytes support explicit structural/body edge classification. */
  private final Map<String, byte[]> classBytes;

  /** Captures the isolated pools whose classes define the graph context. */
  ReferenceGraphIndexer(
      final ClassPool programPool, final ClassPool libraryPool, final Set<String> platformNames) {
    this(programPool, libraryPool, platformNames, Map.of());
  }

  ReferenceGraphIndexer(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformNames,
      final Map<String, byte[]> classBytes) {
    this.programPool = programPool;
    this.libraryPool = libraryPool;
    this.platformNames = platformNames;
    this.classBytes = classBytes;
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
        programPool, libraryPool, libraryInvalidVisitor, edgeFailures);
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
        classBytes,
        edgeFailures);
  }

  private static Function<String, Clazz> classLookup(
      final ClassPool programPool, final ClassPool libraryPool) {
    return name -> {
      final Clazz programClass = programPool.getClass(name);
      return programClass == null ? libraryPool.getClass(name) : programClass;
    };
  }

  static IllegalArgumentException classificationFailure(
      final String className, final RuntimeException cause) {
    return new IllegalArgumentException(
        "Could not classify unclassified reference evidence for class " + className, cause);
  }

  // WHY: ASM reports malformed class records through unchecked failures.
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static ReferenceGraph graph(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformClasses,
      final Function<String, Clazz> classLookup,
      final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries,
      final Map<String, byte[]> classBytes,
      final Map<String, RuntimeException> edgeFailures) {
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges = new HashMap<>();
    classBytes.forEach(
        (name, bytes) -> {
          try {
            typedEdges.put(
                name,
                ClassReferenceEvidence.references(name, bytes, programPool.getClass(name) != null));
          } catch (final RuntimeException exception) {
            edgeFailures.put(name, classificationFailure(name, exception));
          }
        });
    final EdgeCollector collector = new EdgeCollector(programPool, libraryPool, platformClasses);
    for (final Clazz clazz : programPool.classes()) {
      collectEdges(
          clazz, classLookup, signaturePolymorphicResolver, collector, edges, edgeFailures);
    }
    for (final Clazz clazz : libraryPool.classes()) {
      if (!platformClasses.contains(clazz.getName())) {
        collectEdges(
            clazz, classLookup, signaturePolymorphicResolver, collector, edges, edgeFailures);
      }
    }
    recordMissingTypedTargets(
        programPool, classLookup, typedEdges, unresolvedPrograms, unresolvedLibraries);
    typedEdges.forEach(
        (source, targets) ->
            edges.computeIfAbsent(source, ignored -> new TreeSet<>()).addAll(targets.keySet()));
    reconcileTypedEdges(edges, typedEdges, edgeFailures);
    return new ReferenceGraph(
        classNames(programPool),
        classNames(libraryPool, platformClasses),
        immutableSetMap(edges),
        Map.copyOf(typedEdges),
        immutableSetMap(unresolvedPrograms),
        immutableSetMap(unresolvedLibraries),
        Map.copyOf(edgeFailures),
        programPool.size());
  }

  private static void recordMissingTypedTargets(
      final ClassPool programPool,
      final Function<String, Clazz> classLookup,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedPrograms,
      final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolvedLibraries) {
    typedEdges.forEach(
        (source, targets) -> {
          final Map<String, Set<ReferenceGraph.UnresolvedLink>> unresolved =
              programPool.getClass(source) == null ? unresolvedLibraries : unresolvedPrograms;
          targets.forEach(
              (target, kinds) -> {
                if (classLookup.apply(target) == null) {
                  final String evidence =
                      kinds.contains(ReferenceGraph.EdgeKind.STRUCTURAL) ? "structural" : "body";
                  unresolved
                      .computeIfAbsent(source, unused -> new LinkedHashSet<>())
                      .add(
                          new ReferenceGraph.UnresolvedLink(
                              target, source + " -> unresolved " + evidence + " class " + target));
                }
              });
        });
  }

  private static void reconcileTypedEdges(
      final Map<String, Set<String>> completeEdges,
      final Map<String, Map<String, Set<ReferenceGraph.EdgeKind>>> typedEdges,
      final Map<String, RuntimeException> edgeFailures) {
    completeEdges.forEach(
        (source, targets) -> {
          final Set<String> unclassified = new TreeSet<>(targets);
          unclassified.removeAll(typedEdges.getOrDefault(source, Map.of()).keySet());
          if (!unclassified.isEmpty()) {
            edgeFailures.putIfAbsent(
                source,
                new IllegalArgumentException(
                    "Unclassified reference targets in " + source + ": " + unclassified));
          }
        });
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void collectEdges(
      final Clazz clazz,
      final Function<String, Clazz> classLookup,
      final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver,
      final EdgeCollector edgeCollector,
      final Map<String, Set<String>> edges,
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
  }

  private static Set<String> classNames(final ClassPool pool) {
    final Set<String> names = new TreeSet<>();
    pool.classNames().forEachRemaining(names::add);
    return Set.copyOf(names);
  }

  private static Set<String> classNames(final ClassPool pool, final Set<String> excludedNames) {
    final Set<String> names = new TreeSet<>();
    pool.classNames()
        .forEachRemaining(
            name -> {
              if (!excludedNames.contains(name)) {
                names.add(name);
              }
            });
    return Set.copyOf(names);
  }

  private static <T> Map<String, Set<T>> immutableSetMap(final Map<String, Set<T>> source) {
    final Map<String, Set<T>> result = new HashMap<>();
    source.forEach(
        (name, values) ->
            result.put(name, java.util.Collections.unmodifiableSet(new LinkedHashSet<>(values))));
    return Map.copyOf(result);
  }

  /** Collects candidate and sibling nodes, excluding platform classes. */
  private static final class EdgeCollector implements ClassVisitor {
    /** Candidate pool establishes ProgramClass identity precedence. */
    private final ClassPool programPool;

    /** Library class table places siblings before active JDK fallbacks. */
    private final ClassPool libraryPool;

    /** Platform names are excluded from traversal and result accounting. */
    private final Set<String> platformLibraryClasses;

    /** Target set currently receiving ProGuard visitor callbacks. */
    private Set<String> currentEdges = Set.of();

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
    }

    @Override
    public void visitAnyClass(final Clazz clazz) {
      if (programPool.getClass(clazz.getName()) == clazz
          || (libraryPool.getClass(clazz.getName()) == clazz
              && !platformLibraryClasses.contains(clazz.getName()))) {
        currentEdges.add(clazz.getName());
      }
    }
  }
}
