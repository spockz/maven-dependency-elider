// WHY: Gives the transitive test dependency a real archive class for the ban lifecycle fixture.
package io.github.spockz.elider.fixture.testbridge;

import io.github.spockz.elider.fixture.testonly.Marker;

public final class Bridge {
  public String value() {
    return new Marker().value();
  }
}
