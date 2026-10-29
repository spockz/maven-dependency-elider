/* WHY: Verifies that the target-release body's dependency is elevated with it. */

package io.github.spockz.example.mrjar.dependency;

final class TargetHelper {
  private TargetHelper() {}

  static String value() {
    return "target-tier";
  }
}
