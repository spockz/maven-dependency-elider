/* WHY: Makes the test-only builder require a transitive class from its original JAR. */
package io.github.spockz.elider.fixture.testview;

public final class Helper {
  public String value() {
    return "helper";
  }
}
