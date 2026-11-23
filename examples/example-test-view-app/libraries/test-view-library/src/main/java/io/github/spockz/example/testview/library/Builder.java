// WHY: Gives tests a class omitted from a production-retained library.

package io.github.spockz.example.testview.library;

/** Test-facing helper omitted from the production dependency view. */
public final class Builder {
  private Builder() {}

  /** Follows a method-body link into another dropped dependency. */
  public static String build() {
    return "built:" + Helper.value();
  }
}
