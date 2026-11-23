// WHY: Proves tests use omitted Builder and transitive Marker without adding them to production.

package io.github.spockz.example.testview.app;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.example.testview.library.Builder;
import io.github.spockz.example.testview.library.Client;
import org.junit.jupiter.api.Test;

/** Checks class origins when the isolated test runtime is enabled. */
final class TestViewApplicationTest {
  @Test
  void usesOriginalCompilationInputsAndIsolatedRuntimeAdditions() {
    final String built = Builder.build();
    final boolean verifyElision = Boolean.getBoolean("elider.verifyElision");
    assertAll(
        () -> assertEquals("built:helper:marker", built),
        () -> assertEquals("client-ready", Client.message()),
        () -> {
          if (verifyElision) {
            assertTrue(origin(Builder.class).endsWith("/elider/test-additions.jar"));
            assertTrue(origin(Client.class).contains("-trimmed.jar"));
          }
        });
  }

  private static String origin(final Class<?> type) {
    return type.getProtectionDomain().getCodeSource().getLocation().getPath();
  }
}
