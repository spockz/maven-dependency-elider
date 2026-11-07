/* WHY: Owns incremental closure state without retaining mutable ProGuard pools. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Collection;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Map;
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

  /** Last successful policy keeps conservative and bounded graph visits distinct. */
  private ClosureQueryPolicy previousPolicy;

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
    return analyze(requestedRoots, ClosureQueryPolicy.conservative());
  }

  DependencyJarTrimmer.TrimAnalysis analyze(
      final Collection<String> requestedRoots, final ClosureQueryPolicy queryPolicy)
      throws IOException {
    stateLock.lock();
    try {
      return analyzeLocked(requestedRoots, queryPolicy);
    } finally {
      stateLock.unlock();
    }
  }

  private DependencyJarTrimmer.TrimAnalysis analyzeLocked(
      final Collection<String> requestedRoots, final ClosureQueryPolicy queryPolicy)
      throws IOException {
    final Set<String> roots = DependencyJarTrimmer.normalizeRoots(requestedRoots);
    java.util.Objects.requireNonNull(queryPolicy, "queryPolicy");
    if (roots.isEmpty()) {
      return emptyAnalysis(roots);
    }
    validateRoots(roots);
    if (hasCachedAnalysis(roots, queryPolicy)) {
      return previousAnalysis;
    }

    final ReferenceGraph currentGraph = graph();
    final boolean canExtend =
        previousAnalysis != null
            && queryPolicy.equals(previousPolicy)
            && roots.containsAll(previousRoots);
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
            toleratedUnresolvedLibraryClasses,
            queryPolicy);

    final Set<String> retainedClasses = new TreeSet<>(visitedProgramClasses);
    final Set<String> reachableLibraryClasses = new TreeSet<>(visitedLibraryClasses);
    final DependencyJarTrimmer.TrimAnalysis analysis =
        new DependencyJarTrimmer.TrimAnalysis(
            currentGraph.totalClasses(), retainedClasses, roots, reachableLibraryClasses);
    previousRoots = Set.copyOf(roots);
    previousPolicy = queryPolicy;
    previouslyVisitedProgramClasses = Set.copyOf(visitedProgramClasses);
    previouslyVisitedLibraryClasses = Set.copyOf(visitedLibraryClasses);
    previousAnalysis = analysis;
    expandedNodes += additions;
    return analysis;
  }

  private DependencyJarTrimmer.TrimAnalysis emptyAnalysis(final Set<String> roots) {
    return new DependencyJarTrimmer.TrimAnalysis(
        candidateClassNames.size(), Set.of(), roots, Set.of());
  }

  private void validateRoots(final Set<String> roots) {
    final Set<String> missingRoots = new TreeSet<>(roots);
    missingRoots.removeAll(candidateClassNames);
    if (!missingRoots.isEmpty()) {
      throw new IllegalArgumentException(
          "Retained roots are not in candidate JAR: " + missingRoots);
    }
  }

  private boolean hasCachedAnalysis(
      final Set<String> roots, final ClosureQueryPolicy queryPolicy) {
    return previousAnalysis != null
        && roots.equals(previousRoots)
        && queryPolicy.equals(previousPolicy);
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
        final Set<String> toleratedUnresolvedLibraryClasses,
        final ClosureQueryPolicy queryPolicy)
        throws IOException {
      int expanded = 0;
      while (!pending.isEmpty()) {
        final String current = pending.removeFirst();
        if (visitProgram(
            current,
            candidateJar,
            graph,
            visitedProgramClasses,
            tolerateUnresolvedProgramReferences,
            queryPolicy)) {
          expanded++;
        } else if (visitLibrary(
            current,
            candidateJar,
            graph,
            visitedLibraryClasses,
            toleratedUnresolvedLibraryClasses,
            queryPolicy)) {
          expanded++;
        } else {
          continue;
        }
        final RuntimeException edgeFailure = graph.edgeFailures().get(current);
        if (edgeFailure != null) {
          throw edgeFailure;
        }
        enqueueTargets(current, graph, pending, queryPolicy);
      }
      return expanded;
    }

    private static void enqueueTargets(
        final String source,
        final ReferenceGraph graph,
        final Deque<String> pending,
        final ClosureQueryPolicy queryPolicy) {
      if (queryPolicy.mode() == ClosureQueryPolicy.Mode.CONSERVATIVE) {
        graph.edges().getOrDefault(source, Set.of()).forEach(pending::addLast);
        return;
      }
      graph
          .typedEdges()
          .getOrDefault(source, Map.of())
          .forEach(
              (target, kinds) -> {
                if (kinds.contains(ReferenceGraph.EdgeKind.STRUCTURAL)
                    || queryPolicy.allowedClasses().contains(target)) {
                  pending.addLast(target);
                }
              });
    }

    private static boolean visitProgram(
        final String name,
        final Path candidateJar,
        final ReferenceGraph graph,
        final Set<String> visited,
        final boolean tolerateUnresolved,
        final ClosureQueryPolicy queryPolicy)
        throws IOException {
      if (!graph.programClassNames().contains(name) || !visited.add(name)) {
        return false;
      }
      if (!tolerateUnresolved
          && hasFatalUnresolved(
              graph.unresolvedProgramReferences().getOrDefault(name, Set.of()),
              graph,
              name,
              queryPolicy)) {
        throw new DependencyJarTrimmer.UnresolvedReferenceException(
            candidateJar,
            unresolvedDescriptions(
                graph.unresolvedProgramReferences().getOrDefault(name, Set.of()),
                graph,
                name,
                queryPolicy));
      }
      return true;
    }

    private static boolean visitLibrary(
        final String name,
        final Path candidateJar,
        final ReferenceGraph graph,
        final Set<String> visited,
        final Set<String> toleratedUnresolved,
        final ClosureQueryPolicy queryPolicy)
        throws IOException {
      if (!graph.libraryClassNames().contains(name) || !visited.add(name)) {
        return false;
      }
      if (!toleratedUnresolved.contains(name)
          && hasFatalUnresolved(
              graph.unresolvedLibraryReferences().getOrDefault(name, Set.of()),
              graph,
              name,
              queryPolicy)) {
        throw new DependencyJarTrimmer.UnresolvedReferenceException(
            candidateJar,
            unresolvedDescriptions(
                graph.unresolvedLibraryReferences().getOrDefault(name, Set.of()),
                graph,
                name,
                queryPolicy));
      }
      return true;
    }

    private static boolean hasFatalUnresolved(
        final Set<ReferenceGraph.UnresolvedLink> links,
        final ReferenceGraph graph,
        final String source,
        final ClosureQueryPolicy queryPolicy) {
      return links.stream()
          .anyMatch(link -> !isExcludedBodyTarget(link, graph, source, queryPolicy));
    }

    private static Set<String> unresolvedDescriptions(
        final Set<ReferenceGraph.UnresolvedLink> links,
        final ReferenceGraph graph,
        final String source,
        final ClosureQueryPolicy queryPolicy) {
      final Set<String> descriptions = new TreeSet<>();
      links.stream()
          .filter(link -> !isExcludedBodyTarget(link, graph, source, queryPolicy))
          .map(ReferenceGraph.UnresolvedLink::description)
          .forEach(descriptions::add);
      return descriptions;
    }

    private static boolean isExcludedBodyTarget(
        final ReferenceGraph.UnresolvedLink link,
        final ReferenceGraph graph,
        final String source,
        final ClosureQueryPolicy queryPolicy) {
      if (queryPolicy.mode() != ClosureQueryPolicy.Mode.CLOSED_WORLD
          || queryPolicy.allowedClasses().contains(link.targetClass())) {
        return false;
      }
      final Set<ReferenceGraph.EdgeKind> kinds =
          graph.typedEdges().getOrDefault(source, Map.of()).get(link.targetClass());
      return kinds != null
          && kinds.contains(ReferenceGraph.EdgeKind.BODY)
          && !kinds.contains(ReferenceGraph.EdgeKind.STRUCTURAL);
    }
  }
}
