/* WHY: Shares a loopback HTTP fixture across Snyk client regression suites. */

package io.github.spockz.elider.advisory;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.MissingStaticMethodInNonInstantiatableClass"
})
final class SnykPackageIssuesTestSupport {
  private SnykPackageIssuesTestSupport() {
    throw new AssertionError("No instances");
  }

  @FunctionalInterface
  interface ExchangeHandler {
    /** Handles one request from the local Snyk API fixture. */
    void handle(HttpExchange exchange) throws IOException;
  }

  static final class SnykHttpFixture implements AutoCloseable {
    private final HttpServer server;
    private final URI originUri;
    private final List<String> paths = new CopyOnWriteArrayList<>();
    private final List<String> authorizationHeaders = new CopyOnWriteArrayList<>();
    private final AtomicReference<ExchangeHandler> handler =
        new AtomicReference<>(exchange -> reply(exchange, 500, "not configured"));

    /** Starts an ephemeral HTTP server bound to the local loopback interface. */
    @SuppressWarnings("PMD.LawOfDemeter")
    SnykHttpFixture() throws IOException {
      server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
      final InetSocketAddress address = server.getAddress();
      final String host = address.getAddress().getHostAddress();
      originUri =
          URI.create(
              "http://"
                  + (host.indexOf(':') >= 0 ? "[" + host + "]" : host)
                  + ":"
                  + address.getPort());
      server.createContext(
          "/",
          exchange -> {
            paths.add(exchange.getRequestURI().toString());
            authorizationHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
            handler.get().handle(exchange);
          });
      server.start();
    }

    /** Selects a fixed response for subsequent requests. */
    void respond(final int status, final String body) {
      handle(exchange -> reply(exchange, status, body));
    }

    /** Selects request-aware behavior for subsequent requests. */
    void handle(final ExchangeHandler replacement) {
      handler.set(replacement);
    }

    /** Returns the loopback origin used by the Snyk client. */
    URI baseUri() {
      return originUri;
    }

    /** Returns the first request target. */
    String requestPath() {
      return paths.getFirst();
    }

    /** Returns the first authorization header. */
    String authorization() {
      return authorizationHeaders.getFirst();
    }

    /** Returns the number of requests received. */
    int requestCount() {
      return paths.size();
    }

    @SuppressWarnings("PMD.LawOfDemeter")
    static void reply(final HttpExchange exchange, final int status, final String body)
        throws IOException {
      final byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(status, bytes.length);
      try (OutputStream output = exchange.getResponseBody()) {
        output.write(bytes);
      }
    }

    @Override
    public void close() {
      server.stop(0);
    }
  }
}
