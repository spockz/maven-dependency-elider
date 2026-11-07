/* WHY: Carries per-file trace kind and classes through validation and policy identity. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Holds merged observations and their explicit input provenance. */
public record CompositeTraceEvidence(TraceData observations, List<Input> inputs) {
  /** Freezes the observations and input list. */
  public CompositeTraceEvidence {
    observations = java.util.Objects.requireNonNull(observations, "observations");
    inputs = List.copyOf(inputs);
  }

  /** Returns the distinct input kinds in deterministic enum order. */
  public Set<TraceEvidenceKind> inputKinds() {
    final Set<TraceEvidenceKind> kinds = new TreeSet<>();
    inputs.stream().map(Input::kind).forEach(kinds::add);
    return Collections.unmodifiableSet(kinds);
  }

  /** Preserves one explicit input's path, kind, and observations. */
  public record Input(Path path, TraceEvidenceKind kind, TraceData observations) {
    /** Requires complete provenance for each explicitly configured evidence file. */
    public Input {
      java.util.Objects.requireNonNull(path, "path");
      java.util.Objects.requireNonNull(kind, "kind");
      java.util.Objects.requireNonNull(observations, "observations");
    }
  }
}
