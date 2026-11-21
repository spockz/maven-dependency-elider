// WHY: Keeps the selected analysis target distinct from the active JDK runtime in trim results.

package io.github.spockz.elider.plugin;

/** Target and runtime releases used by one elision analysis. */
record TrimExecutionEnvironment(
    int targetRelease, int runtimeRelease, MavenRuntimeCoverage runtimeCoverage) {
  /** Earliest target release supported by the standard JDK contract. */
  private static final int MINIMUM_TARGET_RELEASE = 8;

  /** Earliest supported active runtime release. */
  private static final int MINIMUM_RUNTIME_RELEASE = 21;

  /* package */ TrimExecutionEnvironment(final int targetRelease, final int runtimeRelease) {
    this(targetRelease, runtimeRelease, MavenRuntimeCoverage.EMPTY);
  }

  TrimExecutionEnvironment {
    java.util.Objects.requireNonNull(runtimeCoverage, "runtimeCoverage");
    if (targetRelease < MINIMUM_TARGET_RELEASE) {
      throw new IllegalArgumentException("targetRelease must be at least 8");
    }
    if (runtimeRelease < MINIMUM_RUNTIME_RELEASE) {
      throw new IllegalArgumentException("runtimeRelease must be at least 21");
    }
    if (!java.util.Objects.equals(
        runtimeCoverage.compilerTargetWarning(),
        runtimeCoverage.expectedCompilerTargetWarning(targetRelease))) {
      throw new IllegalArgumentException(
          "The compiler target coverage warning must agree with the inspected and analyzed"
              + " runtimes");
    }
  }
}
