/* WHY: Supplies the Java 17 body that runtime verification must retain after trimming. */

package io.github.spockz.example.mrjar.dependency;

/** Selects a helper implementation from the active multi-release tier. */
public final class MultiReleaseService {
  private MultiReleaseService() {}

  /** Returns a value from the selected tier's helper. */
  public static String value() {
    return UpperHelper.value();
  }
}
