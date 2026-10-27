/* WHY: Supplies removable bytecode so the real elide Mojo must produce a distinct retained JAR. */

package io.github.spockz.elider.fixture.keep;

/** Class omitted from the lifecycle probe's traced JAR. */
public final class UnusedEntry {
  private UnusedEntry() {}

  public static String value() {
    return "unused";
  }
}
