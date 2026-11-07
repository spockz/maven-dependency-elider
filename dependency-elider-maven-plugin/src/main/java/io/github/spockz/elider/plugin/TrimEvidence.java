/* WHY: Keeps trace, compiler, and service evidence together so root planning
 * uses one consistent set of observations. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.TraceData;
import java.util.Set;

/** Root evidence consumed by single-release and tier-aware analysis. */
record TrimEvidence(
    TraceData trace,
    Set<String> sourceRoots,
    Set<String> bytecodeRoots,
    Set<String> projectOutputClasses,
    Set<String> provenServiceInterfaces,
    RuntimeEvidencePolicy runtimePolicy) {
  /* package */ TrimEvidence(
      final TraceData trace,
      final Set<String> sourceRoots,
      final Set<String> bytecodeRoots,
      final Set<String> projectOutputClasses) {
    this(
        trace,
        sourceRoots,
        bytecodeRoots,
        projectOutputClasses,
        Set.of(),
        new RuntimeEvidencePolicy(false, Set.of(), Set.of(), Set.of()));
  }

  /* package */ TrimEvidence(
      final TraceData trace,
      final Set<String> sourceRoots,
      final Set<String> bytecodeRoots,
      final Set<String> projectOutputClasses,
      final Set<String> provenServiceInterfaces) {
    this(
        trace,
        sourceRoots,
        bytecodeRoots,
        projectOutputClasses,
        provenServiceInterfaces,
        new RuntimeEvidencePolicy(false, Set.of(), Set.of(), Set.of()));
  }
}
