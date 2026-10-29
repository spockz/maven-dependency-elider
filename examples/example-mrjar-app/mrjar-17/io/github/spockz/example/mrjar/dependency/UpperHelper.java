/* WHY: Verifies that an upper-tier dependency remains reachable on the runtime JDK. */

package io.github.spockz.example.mrjar.dependency;

final class UpperHelper {
  private UpperHelper() {}

  static String value() {
    return "upper-tier";
  }
}
