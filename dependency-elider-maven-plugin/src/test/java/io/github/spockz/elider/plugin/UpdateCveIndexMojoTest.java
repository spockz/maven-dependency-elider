/* WHY: Verifies the explicit updater publishes only validated typed OSV snapshots. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@SuppressWarnings({
  "PMD.AvoidAccessibilityAlteration",
  "PMD.CommentRequired",
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter"
})
final class UpdateCveIndexMojoTest {
  @TempDir Path temporaryDirectory;

  @Test
  void requiresConfiguredSourceUri() {
    final UpdateCveIndexMojo mojo = newMojo(temporaryDirectory.resolve("cache"), "");
    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoExecutionException.class)
        .hasMessageContaining("elide.osvSnapshotUri");
  }

  @Test
  void publishesGenericSourceSnapshotAndChecksModifiedIndex()
      throws IOException, MojoExecutionException {
    final Path cache = temporaryDirectory.resolve("fresh-cache");
    final AtomicInteger snapshotRequests = new AtomicInteger();
    final AtomicInteger deltaRequests = new AtomicInteger();
    final HttpServer server = server(200, snapshot(), snapshotRequests, deltaRequests);
    server.start();
    try {
      newMojo(cache, endpoint(server)).execute();
      final String persisted = Files.readString(cache.resolve("index.json"));
      assertAll(
          "the update publishes a generic source partition from the snapshot and delta path",
          () ->
              assertThat(persisted)
                  .contains("\"schemaVersion\":1", "\"sources\"", "\"OSV\"", "GHSA-typed")
                  .doesNotContain("\"records\"", "\"mappings\""),
          () -> assertThat(snapshotRequests).hasValue(1),
          () -> assertThat(deltaRequests).hasValue(1));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void failedRefreshPublishesAnExplicitErrorPartition() throws IOException {
    final Path cache = temporaryDirectory.resolve("failed-cache");
    final AtomicInteger snapshotRequests = new AtomicInteger();
    final AtomicInteger deltaRequests = new AtomicInteger();
    final HttpServer server = server(503, "unavailable", snapshotRequests, deltaRequests);
    server.start();
    try {
      assertAll(
          "failed source refresh is reported and persisted as generic source health",
          () ->
              assertThatThrownBy(() -> newMojo(cache, endpoint(server)).execute())
                  .isInstanceOf(MojoExecutionException.class)
                  .hasMessageContaining("HTTP 503"),
          () ->
              assertThat(Files.readString(cache.resolve("index.json")))
                  .contains(
                      "\"schemaVersion\":1",
                      "\"sources\"",
                      "\"OSV\"",
                      "\"status\":\"STALE\"",
                      "HTTP 503")
                  .doesNotContain("\"records\"", "\"mappings\""),
          () -> assertThat(snapshotRequests).hasValue(1),
          () -> assertThat(deltaRequests).hasValue(0));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void refusesUpdateInOfflineSession() throws ReflectiveOperationException {
    final UpdateCveIndexMojo mojo =
        newMojo(temporaryDirectory.resolve("offline-cache"), "http://localhost/all.zip");
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setOffline(true);
    set(
        mojo,
        "session",
        new MavenSession(null, new DefaultRepositorySystemSession(), request, null));
    assertThatThrownBy(mojo::execute)
        .isInstanceOf(MojoExecutionException.class)
        .hasMessageContaining("while Maven is offline");
  }

  private static UpdateCveIndexMojo newMojo(final Path cache, final String uri) {
    final UpdateCveIndexMojo mojo = new UpdateCveIndexMojo();
    mojo.setLog(new SystemStreamLog());
    try {
      set(mojo, "cacheDirectory", cache.toFile());
      set(mojo, "osvSnapshotUri", uri);
      set(mojo, "cveListGitUri", "");
      set(mojo, "pluginDescriptor", MavenPluginDescriptorFixtures.releasedPluginDescriptor());
    } catch (final ReflectiveOperationException exception) {
      throw new IllegalStateException("Could not initialize update-goal fixture", exception);
    }
    return mojo;
  }

  private static HttpServer server(
      final int status,
      final byte[] payload,
      final AtomicInteger snapshotRequests,
      final AtomicInteger deltaRequests)
      throws IOException {
    final HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext(
        "/all.zip",
        exchange -> {
          snapshotRequests.incrementAndGet();
          exchange.getResponseHeaders().set("Last-Modified", "Sat, 31 Oct 2026 00:00:00 GMT");
          exchange.sendResponseHeaders(status, payload.length);
          try (OutputStream output = exchange.getResponseBody()) {
            output.write(payload);
          }
        });
    server.createContext(
        "/modified_id.csv",
        exchange -> {
          deltaRequests.incrementAndGet();
          exchange.sendResponseHeaders(200, 0);
          exchange.getResponseBody().close();
        });
    return server;
  }

  private static HttpServer server(
      final int status,
      final String body,
      final AtomicInteger snapshotRequests,
      final AtomicInteger deltaRequests)
      throws IOException {
    return server(status, body.getBytes(StandardCharsets.UTF_8), snapshotRequests, deltaRequests);
  }

  private static byte[] snapshot() throws IOException {
    final String advisory =
        """
        {"id":"GHSA-typed","modified":"2026-10-31T00:00:00Z","aliases":["CVE-2026-10003"],"affected":[{"package":{"ecosystem":"Maven","name":"org.example:library"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}
        """;
    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(output)) {
      zip.putNextEntry(new ZipEntry("GHSA-typed.json"));
      zip.write(advisory.getBytes(StandardCharsets.UTF_8));
      zip.closeEntry();
    }
    return output.toByteArray();
  }

  private static String endpoint(final HttpServer server) {
    return "http://"
        + server.getAddress().getAddress().getHostAddress()
        + ":"
        + server.getAddress().getPort()
        + "/all.zip";
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    Class<?> current = target.getClass();
    Field field = null;
    while (current != null && field == null) {
      try {
        field = current.getDeclaredField(name);
      } catch (final NoSuchFieldException ignored) {
        current = current.getSuperclass();
      }
    }
    if (field == null) {
      throw new NoSuchFieldException(name);
    }
    field.setAccessible(true);
    field.set(target, value);
  }
}
