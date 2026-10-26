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
import proguard.classfile.util.ClassReferenceInitializer;
import proguard.classfile.util.ClassSuperHierarchyInitializer;
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

  /** Captures the isolated pools whose classes define the graph context. */
  ReferenceGraphIndexer(
      final ClassPool programPool, final ClassPool libraryPool, final Set<String> platformNames) {
    this.programPool = programPool;
    this.libraryPool = libraryPool;
    this.platformNames = platformNames;
  }

  /** Initializes references and freezes the resulting graph. */
  ReferenceGraph build() {
    final Function<String, Clazz> lookup = classLookup(programPool, libraryPool);
    final Map<String, Set<String>> signatureTypes = new HashMap<>();
    final SignaturePolymorphicReferenceResolver signatureResolver =
        new SignaturePolymorphicReferenceResolver(signatureTypes, lookup);
    final Map<String, Set<String>> unresolvedLibraries = new HashMap<>();
    final InvalidReferenceVisitor libraryInvalidVisitor =
        ProGuardReferenceVisitors.recordingLibraryInvalid(unresolvedLibraries, signatureResolver);
    initializeLibraryReferences(programPool, libraryPool, libraryInvalidVisitor);
    final Map<String, Set<String>> unresolvedPrograms = new HashMap<>();
    final InvalidReferenceVisitor programInvalidVisitor =
        ProGuardReferenceVisitors.recordingInvalid(unresolvedPrograms, signatureResolver);
    initializeProgramReferences(programPool, libraryPool, programInvalidVisitor);
    return graph(
        programPool,
        libraryPool,
        platformNames,
        lookup,
        signatureResolver,
        unresolvedPrograms,
        unresolvedLibraries);
  }

  private static Function<String, Clazz> classLookup(
      final ClassPool programPool, final ClassPool libraryPool) {
    return name -> {
      final Clazz programClass = programPool.getClass(name);
      return programClass == null ? libraryPool.getClass(name) : programClass;
    };
  }

  private static void initializeLibraryReferences(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final InvalidReferenceVisitor invalidReferenceVisitor) {
    final ClassSuperHierarchyInitializer hierarchyInitializer =
        new ClassSuperHierarchyInitializer(programPool, libraryPool, invalidReferenceVisitor);
    libraryPool.classesAccept(
        new ClassVisitor() {
          @Override
          public void visitAnyClass(final Clazz clazz) {
            clazz.accept(hierarchyInitializer);
          }
        });
    libraryPool.classesAccept(
        new ClassReferenceInitializer(programPool, libraryPool, false, invalidReferenceVisitor));
  }

  private static void initializeProgramReferences(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final InvalidReferenceVisitor invalidReferenceVisitor) {
    programPool.classesAccept(
        new ClassSuperHierarchyInitializer(programPool, libraryPool, invalidReferenceVisitor));
    programPool.classesAccept(
        new ClassReferenceInitializer(programPool, libraryPool, false, invalidReferenceVisitor));
  }

  private static ReferenceGraph graph(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformClasses,
      final Function<String, Clazz> classLookup,
      final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver,
      final Map<String, Set<String>> unresolvedPrograms,
      final Map<String, Set<String>> unresolvedLibraries) {
    final Map<String, Set<String>> edges = new HashMap<>();
    final Map<String, RuntimeException> edgeFailures = new HashMap<>();
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
    return new ReferenceGraph(
        classNames(programPool),
        classNames(libraryPool, platformClasses),
        immutableSetMap(edges),
        immutableSetMap(unresolvedPrograms),
        immutableSetMap(unresolvedLibraries),
        Map.copyOf(edgeFailures),
        programPool.size());
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
      edgeFailures.put(clazz.getName(), exception);
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

  private static Map<String, Set<String>> immutableSetMap(final Map<String, Set<String>> source) {
    final Map<String, Set<String>> result = new HashMap<>();
    source.forEach(
        (name, values) ->
            result.put(name, java.util.Collections.unmodifiableSet(new LinkedHashSet<>(values))));
    return Map.copyOf(result);
  }

  /** Collects candidate and sibling nodes, excluding platform classes. */
  private static final class EdgeCollector implements ClassVisitor {
    /** Candidate pool establishes ProgramClass identity precedence. */
    private final ClassPool programPool;

    /** Library pool contains first sibling precedence followed by platform fallbacks. */
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
