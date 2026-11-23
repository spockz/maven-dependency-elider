// WHY: Makes a restored class reach a second, entirely dropped artifact.

package io.github.spockz.example.testview.library;

import io.github.spockz.example.testview.marker.Marker;

/** Transitive test-only method-body link. */
public final class Helper {
  private Helper() {}

  /** Uses a class in a separate artifact that production does not need. */
  public static String value() {
    return "helper:" + Marker.value();
  }
}
