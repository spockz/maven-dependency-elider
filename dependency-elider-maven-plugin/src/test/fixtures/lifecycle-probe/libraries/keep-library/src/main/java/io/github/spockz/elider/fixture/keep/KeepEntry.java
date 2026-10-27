/* WHY: Provides the one traced class in the retained JAR for the packaged elide lifecycle probe. */

package io.github.spockz.elider.fixture.keep;

/** Class retained by the lifecycle probe's trace file. */
public final class KeepEntry {
  private KeepEntry() {}

  public static String value() {
    return "keep";
  }
}
