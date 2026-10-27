/* WHY: Keeps the second synthetic dependency in the consumer graph while testing retained-JAR substitution. */

package io.github.spockz.elider.fixture.drop;

/** Class included in the lifecycle probe's trace to avoid testing whole-artifact pruning here. */
public final class DropEntry {
  private DropEntry() {}

  public static String value() {
    return "drop";
  }
}
