/* WHY: Makes conservative and workload-bounded closure queries distinct, including empty bounds. */

package io.github.spockz.elider.trimmer;

import java.util.Objects;
import java.util.Set;

/** Selects which non-structural reference targets may participate in closure. */
public record ClosureQueryPolicy(Mode mode, Set<String> allowedClasses) {
  /** Selects unrestricted static closure or trace-bounded closure. */
  public enum Mode {
    CONSERVATIVE,
    CLOSED_WORLD
  }

  /** Creates an immutable query policy with normalized allowed class names. */
  public ClosureQueryPolicy {
    Objects.requireNonNull(mode, "mode");
    allowedClasses = Set.copyOf(DependencyJarTrimmer.normalizeRoots(allowedClasses));
    if (mode == Mode.CONSERVATIVE && !allowedClasses.isEmpty()) {
      throw new IllegalArgumentException("Conservative closure does not accept an allowed set");
    }
  }

  /** Uses every statically observed class reference. */
  public static ClosureQueryPolicy conservative() {
    return new ClosureQueryPolicy(Mode.CONSERVATIVE, Set.of());
  }

  /** Follows structural edges and body edges to the supplied allowed classes. */
  public static ClosureQueryPolicy closedWorld(final Set<String> allowedClasses) {
    return new ClosureQueryPolicy(Mode.CLOSED_WORLD, allowedClasses);
  }
}
