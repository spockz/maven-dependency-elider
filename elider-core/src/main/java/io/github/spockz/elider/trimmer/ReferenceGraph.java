/* WHY: Stores immutable edges and unresolved-link evidence for one exact analysis context. */

package io.github.spockz.elider.trimmer;

import java.util.Map;
import java.util.Set;

/** Immutable candidate and sibling adjacency captured from isolated ProGuard pools. */
record ReferenceGraph(
    Set<String> programClassNames,
    Set<String> libraryClassNames,
    Map<String, Set<String>> edges,
    Map<String, Map<String, Set<EdgeKind>>> typedEdges,
    Map<String, Set<String>> unclassifiedEdges,
    Map<String, Set<String>> unusedConstantPoolEdges,
    Map<String, Set<String>> unrecognizedClassAttributes,
    Map<String, Set<UnresolvedLink>> unresolvedProgramReferences,
    Map<String, Set<UnresolvedLink>> unresolvedLibraryReferences,
    Map<String, RuntimeException> edgeFailures,
    int totalClasses) {
  /** Distinguishes runtime linkage, executable body, and debug-only references. */
  // WHY: Query callers share the package-private edge vocabulary.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  enum EdgeKind {
    STRUCTURAL,
    BODY,
    DEBUG_METADATA
  }

  /** Identifies a typed target absent from candidate, sibling, and platform pools. */
  // WHY: Query callers share the package-private unresolved-link data shape.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record UnresolvedLink(String targetClass, UnresolvedKind kind, String description) {}

  /** WHY: Query callers distinguish unresolved failure behavior by this closed set. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  enum UnresolvedKind {
    MISSING_CLASS,
    MISSING_MEMBER
  }
}
