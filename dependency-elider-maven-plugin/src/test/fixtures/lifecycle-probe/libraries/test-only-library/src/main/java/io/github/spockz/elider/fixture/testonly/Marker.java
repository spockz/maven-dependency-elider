/* WHY: Proves an independently test-scoped dependency can run without entering the package. */
package io.github.spockz.elider.fixture.testonly;

public final class Marker {
  public String value() {
    return "test-only";
  }
}
