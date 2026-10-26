/* WHY: Owns incremental closure state without retaining mutable ProGuard pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.locks.ReentrantLock;

/** Runs transactional closure queries over one lazily built reference graph. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class PreparedAnalysisState {
  /** Identifies the candidate in unresolved-link diagnostics. */
  private final Path candidateJar;

  /** Supplies the role-scoped graph only when a non-empty closure is requested. */
  private Optional<GraphSupplier> graphSupplier;

  /** Candidate classes are known before ProGuard pools and adjacency are built. */
  private final Set<String> candidateClassNames;

  /** True only for unchanged pass-through program archives. */
  private final boolean tolerateUnresolvedProgramReferences;

  /** Unresolved sibling classes tolerated by this exact role context. */
  private final Set<String> toleratedUnresolvedLibraryClasses;

  /** Serializes graph initialization and incremental state commits. */
  private final ReentrantLock stateLock = new ReentrantLock();

  /** The graph is immutable after its first successful construction. */
  private ReferenceGraph referenceGraph;

  /** Last successful roots enable incremental growth only. */
  private Set<String> previousRoots = Set.of();

  /** Candidate nodes visited by the last successful query. */
  private Set<String> previouslyVisitedProgramClasses = Set.of();

  /** Sibling nodes visited by the last successful query. */
  private Set<String> previouslyVisitedLibraryClasses = Set.of();

  /** Last successful result supports exact-root reuse. */
  private DependencyJarTrimmer.TrimAnalysis previousAnalysis;

  /** Counts successful node expansions for focused performance assertions. */
  private int expandedNodes;

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  PreparedAnalysisState(
      final Path candidateJar,
      final GraphSupplier graphSupplier,
      final Set<String> candidateClassNames,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses) {
    this.candidateJar = candidateJar;
    this.graphSupplier = Optional.of(graphSupplier);
    this.candidateClassNames = Set.copyOf(candidateClassNames);
    this.tolerateUnresolvedProgramReferences = tolerateUnresolvedProgramReferences;
    this.toleratedUnresolvedLibraryClasses = Set.copyOf(toleratedUnresolvedLibraryClasses);
  }

  DependencyJarTrimmer.TrimAnalysis analyze(final Collection<String> requestedRoots)
      throws IOException {
    stateLock.lock();
    try {
      return analyzeLocked(requestedRoots);
    } finally {
      stateLock.unlock();
    }
  }

  private DependencyJarTrimmer.TrimAnalysis analyzeLocked(final Collection<String> requestedRoots)
      throws IOException {
    final Set<String> roots = DependencyJarTrimmer.normalizeRoots(requestedRoots);
    if (roots.isEmpty()) {
      return new DependencyJarTrimmer.TrimAnalysis(
          candidateClassNames.size(), candidateClassNames, roots, Set.of());
    }
    final Set<String> missingRoots = new TreeSet<>(roots);
    missingRoots.removeAll(candidateClassNames);
    if (!missingRoots.isEmpty()) {
      throw new IllegalArgumentException(
          "Retained roots are not in candidate JAR: " + missingRoots);
    }
    if (previousAnalysis != null && roots.equals(previousRoots)) {
      return previousAnalysis;
    }

    final ReferenceGraph currentGraph = graph();
    final boolean canExtend = previousAnalysis != null && roots.containsAll(previousRoots);
    final Set<String> visitedProgramClasses =
        canExtend ? new LinkedHashSet<>(previouslyVisitedProgramClasses) : new LinkedHashSet<>();
    final Set<String> visitedLibraryClasses =
        canExtend ? new LinkedHashSet<>(previouslyVisitedLibraryClasses) : new LinkedHashSet<>();
    final Deque<String> pending = new ArrayDeque<>();
    if (canExtend) {
      roots.stream().filter(root -> !previousRoots.contains(root)).forEach(pending::addLast);
    } else {
      roots.forEach(pending::addLast);
    }
    final int additions =
        ClosureTraversal.visit(
            candidateJar,
            currentGraph,
            pending,
            visitedProgramClasses,
            visitedLibraryClasses,
            tolerateUnresolvedProgramReferences,
            toleratedUnresolvedLibraryClasses);

    final Set<String> retainedClasses = new TreeSet<>(visitedProgramClasses);
    final Set<String> reachableLibraryClasses = new TreeSet<>(visitedLibraryClasses);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer.TrimAnalysis(
            currentGraph.totalClasses(), retainedClasses, roots, reachableLibraryClasses);
    previousRoots = Set.copyOf(roots);
    previouslyVisitedProgramClasses = Set.copyOf(visitedProgramClasses);
    previouslyVisitedLibraryClasses = Set.copyOf(visitedLibraryClasses);
    previousAnalysis = analysis;
    expandedNodes += additions;
    return analysis;
  }

  int expandedNodeCount() {
    stateLock.lock();
    try {
      return expandedNodes;
    } finally {
      stateLock.unlock();
    }
  }

  boolean graphBuilt() {
    stateLock.lock();
    try {
      return referenceGraph != null;
    } finally {
      stateLock.unlock();
    }
  }

  boolean graphSupplierRetained() {
    stateLock.lock();
    try {
      return graphSupplier.isPresent();
    } finally {
      stateLock.unlock();
    }
  }

  private ReferenceGraph graph() throws IOException {
    if (referenceGraph == null) {
      final GraphSupplier supplier = graphSupplier.orElseThrow();
      final ReferenceGraph builtGraph =
          java.util.Objects.requireNonNull(supplier.build(), "graphSupplier result");
      referenceGraph = builtGraph;
      graphSupplier = Optional.empty();
    }
    return referenceGraph;
  }

  /** Defers graph construction until a non-empty closure is requested. */
  @FunctionalInterface
  interface GraphSupplier {
    /** Builds the exact candidate and ordered-sibling context. */
    ReferenceGraph build() throws IOException;
  }

  /** Performs candidate and sibling identity checks for each pending node. */
  private static final class ClosureTraversal {
    private static int visit(
        final Path candidateJar,
        final ReferenceGraph graph,
        final Deque<String> pending,
        final Set<String> visitedProgramClasses,
        final Set<String> visitedLibraryClasses,
        final boolean tolerateUnresolvedProgramReferences,
        final Set<String> toleratedUnresolvedLibraryClasses)
        throws IOException {
      int expanded = 0;
      while (!pending.isEmpty()) {
        final String current = pending.removeFirst();
        if (visitProgram(
            current,
            candidateJar,
            graph,
            visitedProgramClasses,
            tolerateUnresolvedProgramReferences)) {
          expanded++;
        } else if (visitLibrary(
            current,
            candidateJar,
            graph,
            visitedLibraryClasses,
            toleratedUnresolvedLibraryClasses)) {
          expanded++;
        } else {
          continue;
        }
        final RuntimeException edgeFailure = graph.edgeFailures().get(current);
        if (edgeFailure != null) {
          throw edgeFailure;
        }
        graph.edges().getOrDefault(current, Set.of()).forEach(pending::addLast);
      }
      return expanded;
    }

    private static boolean visitProgram(
        final String name,
        final Path candidateJar,
        final ReferenceGraph graph,
        final Set<String> visited,
        final boolean tolerateUnresolved)
        throws IOException {
      if (!graph.programClassNames().contains(name) || !visited.add(name)) {
        return false;
      }
      if (!tolerateUnresolved && graph.unresolvedProgramReferences().containsKey(name)) {
        throw new DependencyJarTrimmer.UnresolvedReferenceException(
            candidateJar, graph.unresolvedProgramReferences().get(name));
      }
      return true;
    }

    private static boolean visitLibrary(
        final String name,
        final Path candidateJar,
        final ReferenceGraph graph,
        final Set<String> visited,
        final Set<String> toleratedUnresolved)
        throws IOException {
      if (!graph.libraryClassNames().contains(name) || !visited.add(name)) {
        return false;
      }
      if (graph.unresolvedLibraryReferences().containsKey(name)
          && !toleratedUnresolved.contains(name)) {
        throw new DependencyJarTrimmer.UnresolvedReferenceException(
            candidateJar, graph.unresolvedLibraryReferences().get(name));
      }
      return true;
    }
  }
}
