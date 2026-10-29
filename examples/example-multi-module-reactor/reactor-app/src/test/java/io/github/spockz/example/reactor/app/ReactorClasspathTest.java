/* WHY: Verifies elided classpath outcome in the multi-module reactor. */

package io.github.spockz.example.reactor.app;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.URL;
import org.junit.jupiter.api.Test;

final class ReactorClasspathTest {

  @Test
  void keepsReactorDependencies() {
    assertNotNull(resource("io/github/spockz/example/reactor/service/ServiceWorker.class"));
    assertNotNull(resource("io/github/spockz/example/reactor/common/CommonHelper.class"));
    assertNotNull(resource("org/apache/commons/compress/archivers/tar/TarArchiveEntry.class"));
  }

  @Test
  void elidesUnusedTransitiveDependencyWhenEnabled() {
    final boolean verifyElision = Boolean.getBoolean("elider.verifyElision");
    final URL codec = resource("org/apache/commons/codec/binary/Base64.class");
    if (verifyElision) {
      assertNull(codec, "commons-codec must be elided from runtime classpath");
    } else {
      assertNotNull(codec, "commons-codec is present on baseline classpath");
    }
  }

  private static URL resource(final String path) {
    return Thread.currentThread().getContextClassLoader().getResource(path);
  }
}
