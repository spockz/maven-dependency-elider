/* WHY: Stores immutable edges and unresolved-link evidence for one exact analysis context. */

package io.github.spockz.elider.trimmer;

import java.util.Map;
import java.util.Set;

/** Immutable candidate and sibling adjacency captured from isolated ProGuard pools. */
record ReferenceGraph(
    Set<String> programClassNames,
    Set<String> libraryClassNames,
    Map<String, Set<String>> edges,
    Map<String, Set<String>> unresolvedProgramReferences,
    Map<String, Set<String>> unresolvedLibraryReferences,
    Map<String, RuntimeException> edgeFailures,
    int totalClasses) {}
