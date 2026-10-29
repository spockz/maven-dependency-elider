/* WHY: Defines the public MRJAR API and the oldest implementation tier. */

package io.github.spockz.example.mrjar.dependency;

/** Selects a helper implementation from the active multi-release tier. */
public final class MultiReleaseService {
  private MultiReleaseService() {}

  /** Returns a value from the selected tier's helper. */
  public static String value() {
    return RootHelper.value();
  }
}
