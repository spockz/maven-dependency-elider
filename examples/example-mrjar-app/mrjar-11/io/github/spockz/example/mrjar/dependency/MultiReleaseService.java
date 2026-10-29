/* WHY: Supplies the Java 11 implementation that is elevated to the root at target 11. */

package io.github.spockz.example.mrjar.dependency;

/** Selects a helper implementation from the active multi-release tier. */
public final class MultiReleaseService {
  private MultiReleaseService() {}

  /** Returns a value from the selected tier's helper. */
  public static String value() {
    return TargetHelper.value();
  }
}
