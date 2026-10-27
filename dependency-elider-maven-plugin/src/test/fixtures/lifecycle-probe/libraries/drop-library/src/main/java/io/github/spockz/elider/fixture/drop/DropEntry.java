/* WHY: Supplies unused bytecode in the synthetic direct dependency that elide can drop. */

package io.github.spockz.elider.fixture.drop;

/** Untraced class that makes the synthetic direct dependency eligible for removal. */
public final class DropEntry {
  private DropEntry() {}

  public static String value() {
    return "drop";
  }
}
