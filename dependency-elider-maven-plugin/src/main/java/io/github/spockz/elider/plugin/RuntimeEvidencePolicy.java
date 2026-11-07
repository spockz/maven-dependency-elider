/* WHY: Keeps admitted runtime policy and provenance immutable for reuse. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.trace.TraceEvidenceKind;
import io.github.spockz.elider.trimmer.ClosureQueryPolicy;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;

/** Canonical identity for runtime evidence policy. */
record RuntimeEvidencePolicy(
    boolean closedWorld,
    Set<String> observedClasses,
    Set<String> allowedClasses,
    Set<TraceEvidenceKind> evidenceKinds) {
  RuntimeEvidencePolicy {
    observedClasses = immutableSorted(observedClasses);
    allowedClasses = immutableSorted(allowedClasses);
    evidenceKinds = immutableSortedKinds(evidenceKinds);
  }

  /* default */ ClosureQueryPolicy closureQueryPolicy() {
    return closedWorld
        ? ClosureQueryPolicy.closedWorld(allowedClasses)
        : ClosureQueryPolicy.conservative();
  }

  private static Set<String> immutableSorted(final Set<String> values) {
    final Set<String> normalized = new TreeSet<>();
    values.forEach(value -> normalized.add(TraceData.normalizeToDot(value.trim())));
    return Collections.unmodifiableSet(normalized);
  }

  private static Set<TraceEvidenceKind> immutableSortedKinds(final Set<TraceEvidenceKind> values) {
    return Collections.unmodifiableSet(new TreeSet<>(values));
  }
}
