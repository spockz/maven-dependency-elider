/* WHY: Keeps scan scope and completion evidence with static references, distinguishing empty
 * results from missing or failed production output. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.TraceData;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/** Immutable evidence from one explicitly scoped production bytecode scan. */
public record BytecodeReferenceScan(
    Path scope, Set<String> referencedClasses, int classFilesScanned, boolean complete) {
  /** Copies and sorts class names to provide deterministic immutable results. */
  public BytecodeReferenceScan {
    scope = Objects.requireNonNull(scope, "scope").toAbsolutePath().normalize();
    Objects.requireNonNull(referencedClasses, "referencedClasses");
    if (classFilesScanned < 0) {
      throw new IllegalArgumentException("classFilesScanned must not be negative");
    }
    final SortedSet<String> sorted = new TreeSet<>();
    for (final String className : referencedClasses) {
      sorted.add(TraceData.normalizeToDot(Objects.requireNonNull(className, "class name")));
    }
    referencedClasses = Collections.unmodifiableSet(sorted);
  }
}
