// WHY: Demonstrates a dependency dropped from production but reached transitively by a test builder.

package io.github.spockz.example.testview.marker;

/** Value supplied only to the test runtime. */
public final class Marker {
  private Marker() {}

  /** Returns a stable marker for the example assertion. */
  public static String value() {
    return "marker";
  }
}
