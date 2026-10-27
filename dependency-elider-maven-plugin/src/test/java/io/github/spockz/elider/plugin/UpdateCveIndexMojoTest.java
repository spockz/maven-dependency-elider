/* WHY: Proves the explicit index update goal refreshes or fails instead of falling back silently.
 */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager.CacheConfig;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.SystemStreamLog;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies observable update-goal refresh and failure behavior. */
@SuppressWarnings({"PMD.AvoidAccessibilityAlteration", "PMD.CommentDefaultAccessModifier"})
final class UpdateCveIndexMojoTest {
  /** Valid empty document used to seed a fresh cache. */
  private static final String EMPTY_INDEX = "{\"mappings\":[]}";

  /** Cache file names used by isolated refresh fixtures. */
  private static final String INDEX_FILE = "index.json";

  /** Temporary file used while an index refresh is validated. */
  private static final String TEMPORARY_INDEX_FILE = "index.json.tmp";

  /** Syntactically valid mapping document with an invalid Maven version range. */
  private static final String INVALID_RANGE_INDEX =
      "{\"mappings\":[{\"cveId\":\"CVE-2026-10003\","
          + "\"affectedCoordinate\":{\"groupId\":\"org.example\","
          + "\"artifactId\":\"library\",\"version\":\"1.0\","
          + "\"type\":\"jar\",\"classifier\":\"\",\"scope\":\"compile\"},"
          + "\"versionRangeSpec\":\"[1.0,2.0\",\"vulnerableClasses\":[\"sample.Bad\"],"
          + "\"sourceAdvisoryUrl\":null,\"confidenceLevel\":\"HIGH\"}]}";

  /** Isolated project-like directory for each cache test. */
  @TempDir private Path temporaryDirectory;

  /** Creates the test class without shared Maven state. */
  UpdateCveIndexMojoTest() {
    super();
  }

  /** Verifies required configuration for explicit cache refresh. */
  @Nested
  final class SourceConfigurationTests {
    /** Creates the source-configuration test cases. */
    SourceConfigurationTests() {
      super();
    }

    @Test
    void requiresConfiguredSourceUri() {
      final UpdateCveIndexMojo mojo = newMojo(temporaryDirectory.resolve("cache"), null);

      assertThatThrownBy(mojo::execute)
          .isInstanceOf(MojoExecutionException.class)
          .hasMessageContaining("elide.cveIndexUri");
    }
  }

  /** Verifies refresh success and failure behavior. */
  @Nested
  final class RefreshBehaviorTests {
    /** Creates the refresh-behavior test cases. */
    RefreshBehaviorTests() {
      super();
    }

    @Test
    void refreshesEvenWhenCacheIsFresh() throws IOException, MojoExecutionException {
      final Path cache = temporaryDirectory.resolve("fresh-cache");
      Files.createDirectories(cache);
      final Path index = cache.resolve(INDEX_FILE);
      Files.writeString(index, EMPTY_INDEX);
      Files.setLastModifiedTime(index, FileTime.from(Instant.now()));
      final AtomicInteger requests = new AtomicInteger();
      final TestServer server = server(200, EMPTY_INDEX, requests);
      server.httpServer().start();
      try {
        final UpdateCveIndexMojo mojo = newMojo(cache, server.uri());

        mojo.execute();

        assertThat(
                new RefreshObservation(
                    requests.get(),
                    Files.readString(index),
                    Files.exists(cache.resolve(TEMPORARY_INDEX_FILE))))
            .isEqualTo(new RefreshObservation(1, EMPTY_INDEX, false));
      } finally {
        server.httpServer().stop(0);
      }
    }

    @Test
    void refreshFailureFailsEvenWhenValidCacheCanBeLoaded() throws IOException {
      final Path cache = temporaryDirectory.resolve("fallback-cache");
      Files.createDirectories(cache);
      final Path index = cache.resolve(INDEX_FILE);
      Files.writeString(index, EMPTY_INDEX);
      final AtomicInteger requests = new AtomicInteger();
      final TestServer server = server(503, "unavailable", requests);
      server.httpServer().start();
      try {
        final UpdateCveIndexMojo mojo = newMojo(cache, server.uri());

        final MojoExecutionException failure = executionFailure(mojo);
        assertThat(
                new FailureObservation(
                    failure == null ? "" : failure.getMessage(),
                    requests.get(),
                    Files.readString(index),
                    Files.exists(cache.resolve(TEMPORARY_INDEX_FILE))))
            .isEqualTo(
                new FailureObservation(
                    "Could not update vulnerability mapping index: "
                        + "Vulnerability index refresh failed: Source returned HTTP 503",
                    1,
                    EMPTY_INDEX,
                    false));
      } finally {
        server.httpServer().stop(0);
      }
    }
  }

  /** Verifies Maven version ranges before accepting an updated cache. */
  @Nested
  final class RangeValidationTests {
    /** Creates the range-validation test cases. */
    RangeValidationTests() {
      super();
    }

    @Test
    void downloadedIndexWithMalformedMavenRangeFailsWithMappingIdentity() throws IOException {
      final Path cache = temporaryDirectory.resolve("invalid-range-cache");
      Files.createDirectories(cache);
      final Path index = cache.resolve(INDEX_FILE);
      Files.writeString(index, EMPTY_INDEX);
      final AtomicInteger requests = new AtomicInteger();
      final TestServer server = server(200, INVALID_RANGE_INDEX, requests);
      server.httpServer().start();
      try {
        final UpdateCveIndexMojo mojo = newMojo(cache, server.uri());

        final MojoExecutionException failure = executionFailure(mojo);
        assertThat(
                new FailureObservation(
                    failure == null ? "" : failure.getMessage(),
                    requests.get(),
                    Files.readString(index),
                    Files.exists(cache.resolve(TEMPORARY_INDEX_FILE))))
            .isEqualTo(
                new FailureObservation(
                    "Could not update vulnerability mapping index: "
                        + "Vulnerability index refresh failed: "
                        + "Invalid Maven version range in downloaded vulnerability index for "
                        + "CVE-2026-10003 org.example:library:jar:1.0: [1.0,2.0",
                    1,
                    EMPTY_INDEX,
                    false));

      } finally {
        server.httpServer().stop(0);
      }
    }

    @Test
    void normalAssessmentRejectsMalformedDownloadBeforeOfflineFallback() throws IOException {
      final Path cache = temporaryDirectory.resolve("assessment-cache");
      Files.createDirectories(cache);
      final Path index = cache.resolve(INDEX_FILE);
      Files.writeString(index, EMPTY_INDEX);
      final AtomicInteger requests = new AtomicInteger();
      final TestServer server = server(200, INVALID_RANGE_INDEX, requests);
      server.httpServer().start();
      try {
        final MavenVulnerabilityAssessment assessment =
            new MavenVulnerabilityAssessment(new SystemStreamLog());
        final CacheConfig onlineConfig =
            new CacheConfig(
                cache,
                URI.create(server.uri()),
                Duration.ofHours(24),
                true,
                false,
                VulnerabilityCacheManager.bundledEmptySeed());
        final int onlineAttestations = assessment.assess(onlineConfig, List.of(), List.of()).size();
        final String cacheAfterOnlineRefresh = Files.readString(index);
        final CacheConfig offlineConfig =
            new CacheConfig(
                cache,
                URI.create(server.uri()),
                Duration.ofHours(24),
                true,
                true,
                VulnerabilityCacheManager.bundledEmptySeed());
        final int offlineAttestations =
            assessment.assess(offlineConfig, List.of(), List.of()).size();

        assertThat(
                new AssessmentFallbackObservation(
                    onlineAttestations,
                    requests.get(),
                    cacheAfterOnlineRefresh,
                    Files.exists(cache.resolve(TEMPORARY_INDEX_FILE)),
                    offlineAttestations,
                    Files.readString(index)))
            .isEqualTo(new AssessmentFallbackObservation(0, 1, EMPTY_INDEX, false, 0, EMPTY_INDEX));
      } finally {
        server.httpServer().stop(0);
      }
    }
  }

  /** Verifies update-goal behavior in offline Maven sessions. */
  @Nested
  final class OfflineBehaviorTests {
    /** Creates the offline-behavior test cases. */
    OfflineBehaviorTests() {
      super();
    }

    @Test
    void refusesUpdateInOfflineSession() throws ReflectiveOperationException {
      final UpdateCveIndexMojo mojo =
          newMojo(temporaryDirectory.resolve("offline-cache"), "http://localhost/index");
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
  }

  private static UpdateCveIndexMojo newMojo(final Path cache, final String uri) {
    final UpdateCveIndexMojo mojo = new UpdateCveIndexMojo();
    mojo.setLog(new SystemStreamLog());
    try {
      set(mojo, "cacheDirectory", cache.toFile());
      set(mojo, "indexUri", uri);
    } catch (final ReflectiveOperationException exception) {
      throw new IllegalStateException("Could not initialize update-goal fixture", exception);
    }
    return mojo;
  }

  private static TestServer server(
      final int status, final String body, final AtomicInteger requests) throws IOException {
    final InetAddress loopback = InetAddress.getLoopbackAddress();
    final InetSocketAddress address = new InetSocketAddress(loopback, 0);
    final HttpServer server = HttpServer.create(address, 0);
    server.createContext(
        "/index",
        exchange -> {
          requests.incrementAndGet();
          final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status, bytes.length);
          try (OutputStream response = exchange.getResponseBody()) {
            response.write(bytes);
          }
        });
    return new TestServer(server, endpoint(server));
  }

  /** Builds a URI from the ephemeral address assigned to the test HTTP listener. */
  @SuppressWarnings("PMD.LawOfDemeter")
  private static String endpoint(final HttpServer server) {
    try {
      final InetSocketAddress boundAddress = server.getAddress();
      final InetAddress boundInetAddress = boundAddress.getAddress();
      final URI uri =
          new URI(
              "http",
              null,
              boundInetAddress.getHostAddress(),
              boundAddress.getPort(),
              "/index",
              null,
              null);
      return uri.toString();
    } catch (final URISyntaxException exception) {
      throw new IllegalStateException("Could not construct loopback test URI", exception);
    }
  }

  private static void set(final Object target, final String name, final Object value)
      throws ReflectiveOperationException {
    final Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static MojoExecutionException executionFailure(final UpdateCveIndexMojo mojo) {
    try {
      mojo.execute();
      return null;
    } catch (final MojoExecutionException failure) {
      return failure;
    }
  }

  private record TestServer(HttpServer httpServer, String uri) {}

  private record RefreshObservation(int requests, String content, boolean temporaryFileExists) {}

  private record FailureObservation(
      String message, int requests, String cacheContent, boolean temporaryFileExists) {}

  private record AssessmentFallbackObservation(
      int onlineAttestations,
      int requests,
      String cacheAfterOnlineRefresh,
      boolean temporaryFileExists,
      int offlineAttestations,
      String cacheAfterOfflineRead) {}
}
