/* WHY: Gives the base implementation a helper that target elevation can omit. */

package io.github.spockz.example.mrjar.dependency;

final class RootHelper {
  private RootHelper() {}

  static String value() {
    return "root-tier";
  }
}
