/* WHY: Checks original compilation inputs and actual runtime origins of both dependency views. */
package app;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.elider.fixture.testonly.Marker;
import io.github.spockz.elider.fixture.testview.Builder;
import io.github.spockz.elider.fixture.testview.Client;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

final class AppTest {
  @Test
  void usesTrimmedProductionAndTestAddition() throws Exception {
    assertAll(
        "test dependency views and user classpath entry",
        () -> assertEquals("client", new App().run()),
        () -> assertEquals("helper", new Builder().build()),
        () -> assertEquals("test-only", new Marker().value()),
        () -> assertTrue(origin(Client.class).contains("trimmed.jar"), origin(Client.class)),
        () -> assertTrue(origin(Builder.class).contains("test-additions.jar"), origin(Builder.class)),
        () -> assertTrue(origin(Marker.class).contains("test-additions.jar"), origin(Marker.class)),
        () -> {
          final URL resource = Client.class.getResource("/fixture/test-view-resource.txt");
          assertNotNull(resource);
          assertTrue(resource.toString().contains("trimmed.jar"), resource.toString());
          try (var input = resource.openStream()) {
            assertTrue(new String(input.readAllBytes(), StandardCharsets.UTF_8).contains("production-resource"));
          }
        },
        () ->
            assertTrue(
                getClass().getResource(
                        "/"
                            + System.getProperty(
                                "adr0016.executionMarker", "user-classpath-marker.txt"))
                    != null));
  }

  private static String origin(final Class<?> type) {
    return type.getProtectionDomain().getCodeSource().getLocation().toString();
  }
}
