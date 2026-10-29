/* WHY: Unit test for CommonHelper verifying runtime behavior. */

package io.github.spockz.example.reactor.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

final class CommonHelperTest {

  @Test
  void describesTarEntry() {
    assertEquals("test.tar", CommonHelper.describeTarEntry("test.tar"));
  }
}
