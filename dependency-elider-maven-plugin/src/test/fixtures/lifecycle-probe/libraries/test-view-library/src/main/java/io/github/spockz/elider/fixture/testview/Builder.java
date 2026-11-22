/* WHY: Supplies a test-referenced class that production reachability should trim. */
package io.github.spockz.elider.fixture.testview;

public final class Builder {
  public String build() {
    return new Helper().value();
  }
}
