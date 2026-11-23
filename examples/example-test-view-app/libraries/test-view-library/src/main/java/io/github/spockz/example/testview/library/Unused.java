// WHY: Shows that the production package also omits code unused by both production and tests.

package io.github.spockz.example.testview.library;

/** Dead production code that the test-only conservative fallback may restore. */
public final class Unused {
  private Unused() {}

  /** Returns a recognizable value if the production package accidentally retains it. */
  public static String value() {
    return "unused";
  }
}
