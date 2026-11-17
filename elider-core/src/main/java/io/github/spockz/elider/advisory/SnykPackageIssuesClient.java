/* WHY: Provides the authenticated Snyk package issues API boundary. */

package io.github.spockz.elider.advisory;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Queries Snyk issues for one exact Maven package version. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.TooManyMethods"})
public final class SnykPackageIssuesClient {
  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

  private final HttpClient client;
  private final URI apiBaseUri;
  private final String orgId;
  private final String token;
  private final SnykPackageIssuesResponseReader responseReader =
      new SnykPackageIssuesResponseReader();

  /** Creates an API client with redirects disabled and bounded request timeouts. */
  public SnykPackageIssuesClient(final URI apiBaseUri, final String orgId, final String token) {
    this.apiBaseUri = validateBaseUri(apiBaseUri);
    this.orgId = requireText(orgId, "orgId");
    this.token = token;
    this.client =
        HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  /** Queries issues for exactly the provided Maven coordinate. */
  public SnykPackageIssuesResult query(final ArtifactCoordinate coordinate) {
    Objects.requireNonNull(coordinate, "coordinate");
    final String coordinateProblem = coordinateProblem(coordinate);
    if (coordinateProblem != null) {
      return failed(coordinate, coordinateProblem);
    }
    if (!validToken(token)) {
      return failed(coordinate, "Snyk authorization token is invalid");
    }
    return queryValidCoordinate(coordinate);
  }

  // Queries are sequential; interrupted requests restore the interrupt flag.
  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.DoNotUseThreads",
    "PMD.UseConcurrentHashMap"
  })
  private SnykPackageIssuesResult queryValidCoordinate(final ArtifactCoordinate coordinate) {
    final URI endpoint = SnykPackageIssuesPagination.endpointFor(apiBaseUri, orgId, coordinate);
    final Map<String, VulnerabilityFindingContribution> contributions = new LinkedHashMap<>();
    final List<String> diagnostics = new ArrayList<>();
    final Set<URI> visitedPages = new LinkedHashSet<>();
    URI nextPage = SnykPackageIssuesPagination.firstPage(endpoint);
    int currentOffset = 0;
    int pagesRead = 0;
    while (nextPage != null) {
      if (!visitedPages.add(nextPage)) {
        return failedPage(
            coordinate, pagesRead, contributions, diagnostics, "Snyk pagination repeated a page");
      }
      final HttpResponse<byte[]> response;
      try {
        response = send(nextPage);
      } catch (final IOException exception) {
        return failedPage(
            coordinate,
            pagesRead,
            contributions,
            diagnostics,
            "Snyk request could not be completed");
      } catch (final InterruptedException exception) {
        Thread.currentThread().interrupt();
        return failedPage(
            coordinate, pagesRead, contributions, diagnostics, "Snyk request was interrupted");
      }
      if (!successful(response)) {
        return failedPage(
            coordinate,
            pagesRead,
            contributions,
            diagnostics,
            "Snyk request failed with HTTP status " + response.statusCode());
      }
      final SnykPackageIssuesResponseReader.Page page;
      try {
        page = responseReader.read(response.body(), coordinate);
      } catch (final IOException | IllegalArgumentException exception) {
        return failedPage(
            coordinate,
            pagesRead,
            contributions,
            diagnostics,
            "Snyk response did not identify the requested package version");
      }
      mergePage(contributions, page.contributions());
      diagnostics.addAll(page.diagnostics());
      pagesRead++;
      final SnykPackageIssuesPagination.Page pagination =
          SnykPackageIssuesPagination.nextPage(
              endpoint, page.nextLink(), currentOffset, page.rowsReturned());
      if (pagination.invalid() || page.invalidPagination()) {
        return partialPage(
            coordinate, contributions, diagnostics, "Snyk pagination link was invalid");
      }
      nextPage = pagination.uri();
      if (nextPage != null) {
        currentOffset = pagination.offset();
      }
    }
    return new SnykPackageIssuesResult(
        coordinate,
        diagnostics.isEmpty()
            ? SnykPackageIssuesResult.Status.COMPLETE
            : SnykPackageIssuesResult.Status.PARTIAL,
        List.copyOf(contributions.values()),
        diagnostics);
  }

  private HttpResponse<byte[]> send(final URI target) throws IOException, InterruptedException {
    final HttpRequest request =
        HttpRequest.newBuilder(target)
            .timeout(REQUEST_TIMEOUT)
            .header("Authorization", "token " + token)
            .header("Accept", "application/vnd.api+json")
            .GET()
            .build();
    return client.send(request, HttpResponse.BodyHandlers.ofByteArray());
  }

  private static void mergePage(
      final Map<String, VulnerabilityFindingContribution> allContributions,
      final List<VulnerabilityFindingContribution> pageContributions) {
    pageContributions.forEach(
        contribution ->
            allContributions.merge(
                contribution.vulnerabilityId(),
                contribution,
                SnykPackageIssuesResponseReader::mergeDuplicate));
  }

  private static boolean successful(final HttpResponse<?> response) {
    return response.statusCode() >= 200 && response.statusCode() < 300;
  }

  private static SnykPackageIssuesResult failedPage(
      final ArtifactCoordinate coordinate,
      final int pagesRead,
      final Map<String, VulnerabilityFindingContribution> contributions,
      final List<String> diagnostics,
      final String diagnostic) {
    final SnykPackageIssuesResult.Status status =
        pagesRead == 0
            ? SnykPackageIssuesResult.Status.FAILED
            : SnykPackageIssuesResult.Status.PARTIAL;
    return resultWithDiagnostic(coordinate, status, contributions, diagnostics, diagnostic);
  }

  private static SnykPackageIssuesResult partialPage(
      final ArtifactCoordinate coordinate,
      final Map<String, VulnerabilityFindingContribution> contributions,
      final List<String> diagnostics,
      final String diagnostic) {
    return resultWithDiagnostic(
        coordinate, SnykPackageIssuesResult.Status.PARTIAL, contributions, diagnostics, diagnostic);
  }

  private static SnykPackageIssuesResult resultWithDiagnostic(
      final ArtifactCoordinate coordinate,
      final SnykPackageIssuesResult.Status status,
      final Map<String, VulnerabilityFindingContribution> contributions,
      final List<String> diagnostics,
      final String diagnostic) {
    final List<String> allDiagnostics = new ArrayList<>(diagnostics);
    allDiagnostics.add(diagnostic);
    return new SnykPackageIssuesResult(
        coordinate, status, List.copyOf(contributions.values()), allDiagnostics);
  }

  private static String coordinateProblem(final ArtifactCoordinate coordinate) {
    if (coordinate.version() == null || coordinate.version().isBlank()) {
      return "Snyk package query requires an exact version";
    }
    if (coordinate.groupId().isBlank() || coordinate.artifactId().isBlank()) {
      return "Snyk package query requires Maven group and artifact identifiers";
    }
    if (!"jar".equalsIgnoreCase(coordinate.type()) || !coordinate.classifier().isBlank()) {
      return "Snyk package query does not support this Maven type or classifier";
    }
    return null;
  }

  private static boolean validToken(final String value) {
    return value != null
        && !value.isBlank()
        && value.chars().allMatch(character -> character >= 33 && character <= 126);
  }

  private static SnykPackageIssuesResult failed(
      final ArtifactCoordinate coordinate, final String diagnostic) {
    return new SnykPackageIssuesResult(
        coordinate, SnykPackageIssuesResult.Status.FAILED, List.of(), List.of(diagnostic));
  }

  private static URI validateBaseUri(final URI uri) {
    Objects.requireNonNull(uri, "apiBaseUri");
    if (!uri.isAbsolute() || uri.getHost() == null || !httpScheme(uri)) {
      throw new IllegalArgumentException("apiBaseUri must be an HTTP(S) origin");
    }
    if (!originOnly(uri)) {
      throw new IllegalArgumentException("apiBaseUri must be an HTTP(S) origin");
    }
    return uri;
  }

  private static boolean originOnly(final URI uri) {
    return uri.getRawUserInfo() == null
        && uri.getRawQuery() == null
        && uri.getRawFragment() == null
        && !hasNonRootPath(uri);
  }

  private static boolean httpScheme(final URI uri) {
    return "https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme());
  }

  private static boolean hasNonRootPath(final URI uri) {
    final String rawPath = uri.getRawPath();
    return rawPath != null && !rawPath.isEmpty() && !"/".equals(rawPath);
  }

  private static String requireText(final String value, final String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must not be blank");
    }
    return value;
  }
}
