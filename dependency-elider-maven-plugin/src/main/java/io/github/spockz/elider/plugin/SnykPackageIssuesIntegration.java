// WHY: Keeps optional per-coordinate Snyk lookups isolated from shared advisory-cache state.

package io.github.spockz.elider.plugin;

import static io.github.spockz.elider.advisory.SnykPackageIssuesResult.Status.COMPLETE;
import static io.github.spockz.elider.advisory.SnykPackageIssuesResult.Status.FAILED;

import io.github.spockz.elider.advisory.FindingContributionJsonCodec;
import io.github.spockz.elider.advisory.FindingSource;
import io.github.spockz.elider.advisory.SnykPackageIssuesClient;
import io.github.spockz.elider.advisory.SnykPackageIssuesResult;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Runs the explicitly enabled Snyk package issue lookups for one Maven assessment. */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.CommentDefaultAccessModifier"})
final class SnykPackageIssuesIntegration {
  /** Permitted HTTPS origins that may receive a Snyk API token. */
  private static final Set<String> OFFICIAL_API_HOSTS =
      Set.of("api.snyk.io", "api.us.snyk.io", "api.eu.snyk.io", "api.au.snyk.io");

  /** Injected query boundary for isolated assessment tests. */
  @FunctionalInterface
  /* default */ interface Query {
    /** Queries one exact Maven coordinate. */
    SnykPackageIssuesResult query(ArtifactCoordinate coordinate);
  }

  /** Immutable lookup results and aggregate source health for one analysis. */
  /* default */ record Result(
      Map<ArtifactCoordinate, SnykPackageIssuesResult> results,
      Optional<FindingSourceObservation> observation) {
    Result {
      results = Map.copyOf(Objects.requireNonNull(results, "results"));
      Objects.requireNonNull(observation, "observation");
    }

    List<VulnerabilityFindingContribution> contributionsFor(
        final ArtifactCoordinate exactCoordinate) {
      final SnykPackageIssuesResult result = results.get(exactCoordinate);
      return result == null ? List.of() : result.contributions();
    }
  }

  /** Runtime switches and a credential-bearing query closure. */
  /* default */ record Configuration(
      boolean enabled, boolean offline, boolean credentialsAvailable, Query query) {
    static Configuration disabled() {
      return new Configuration(false, false, false, null);
    }

    static Configuration configured(
        final boolean enabled,
        final boolean offline,
        final String configuredOrgId,
        final String apiBaseUri) {
      final String orgId =
          configuredOrgId == null || configuredOrgId.isBlank()
              ? System.getenv("SNYK_ORG_ID")
              : configuredOrgId;
      final String token = System.getenv("SNYK_TOKEN");
      final boolean credentialsAvailable =
          orgId != null && !orgId.isBlank() && token != null && !token.isBlank();
      final Query query =
          enabled && !offline && credentialsAvailable
              ? new SnykPackageIssuesClient(validateApiBaseUri(apiBaseUri), orgId, token)::query
              : null;
      return new Configuration(enabled, offline, credentialsAvailable, query);
    }
  }

  private SnykPackageIssuesIntegration() {}

  static URI validateApiBaseUri(final String value) {
    final URI uri;
    try {
      uri = URI.create(Objects.requireNonNull(value, "apiBaseUri"));
    } catch (final IllegalArgumentException exception) {
      throw new IllegalArgumentException("Snyk API base URI is invalid", exception);
    }
    if (!validOrigin(uri)) {
      throw new IllegalArgumentException(
          "Snyk API base URI must be an official HTTPS regional origin");
    }
    return URI.create("https://" + uri.getHost().toLowerCase(java.util.Locale.ROOT));
  }

  private static boolean validOrigin(final URI uri) {
    return "https".equalsIgnoreCase(uri.getScheme())
        && OFFICIAL_API_HOSTS.contains(normalizedHost(uri))
        && validPort(uri)
        && hasNoEndpointComponents(uri);
  }

  private static String normalizedHost(final URI uri) {
    return uri.getHost() == null ? "" : uri.getHost().toLowerCase(java.util.Locale.ROOT);
  }

  private static boolean validPort(final URI uri) {
    return uri.getPort() == -1 || uri.getPort() == 443;
  }

  private static boolean hasNoEndpointComponents(final URI uri) {
    final String path = uri.getRawPath();
    return uri.getRawUserInfo() == null
        && uri.getRawQuery() == null
        && uri.getRawFragment() == null
        && (path == null || path.isEmpty() || "/".equals(path));
  }

  static Result collect(
      final Collection<ArtifactCoordinate> candidates,
      final boolean enabled,
      final boolean offline,
      final String orgId,
      final String token,
      final Query query) {
    Objects.requireNonNull(candidates, "candidates");
    if (!enabled) {
      return new Result(Map.of(), Optional.empty());
    }
    if (offline) {
      return unavailable("Snyk package issue lookup skipped because Maven is offline");
    }
    if (orgId == null || orgId.isBlank() || token == null || token.isBlank()) {
      return error("Snyk package issue lookup requires an organization ID and SNYK_TOKEN");
    }
    return queryCandidates(candidates, query);
  }

  static Result collect(
      final Collection<ArtifactCoordinate> candidates, final Configuration configuration) {
    Objects.requireNonNull(configuration, "configuration");
    if (!configuration.enabled()) {
      return new Result(Map.of(), Optional.empty());
    }
    if (configuration.offline()) {
      return unavailable("Snyk package issue lookup skipped because Maven is offline");
    }
    if (!configuration.credentialsAvailable()) {
      return error("Snyk package issue lookup requires an organization ID and SNYK_TOKEN");
    }
    return queryCandidates(candidates, configuration.query());
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Result queryCandidates(
      final Collection<ArtifactCoordinate> candidates, final Query query) {
    Objects.requireNonNull(candidates, "candidates");
    Objects.requireNonNull(query, "query");
    final List<ArtifactCoordinate> distinctCandidates =
        candidates.stream().distinct().sorted(Comparator.naturalOrder()).toList();
    if (distinctCandidates.isEmpty()) {
      return unavailable("Snyk package issue lookup had no Maven artifact candidates");
    }
    final Map<ArtifactCoordinate, SnykPackageIssuesResult> results = new LinkedHashMap<>();
    for (final ArtifactCoordinate coordinate : distinctCandidates) {
      final SnykPackageIssuesResult result = query.query(coordinate);
      if (coordinate.equals(result.coordinate())) {
        results.put(coordinate, result);
      } else {
        results.put(coordinate, failed(coordinate));
      }
    }
    return new Result(results, Optional.of(observation(results)));
  }

  private static Result unavailable(final String diagnostic) {
    return new Result(
        Map.of(),
        Optional.of(
            new FindingSourceObservation(
                Optional.of(FindingSource.SNYK),
                FindingSourceObservation.Status.UNAVAILABLE,
                null,
                null,
                diagnostic,
                List.of(),
                0)));
  }

  private static Result error(final String diagnostic) {
    return new Result(
        Map.of(),
        Optional.of(
            new FindingSourceObservation(
                Optional.of(FindingSource.SNYK),
                FindingSourceObservation.Status.ERROR,
                null,
                null,
                diagnostic,
                List.of(),
                0)));
  }

  private static SnykPackageIssuesResult failed(final ArtifactCoordinate coordinate) {
    return new SnykPackageIssuesResult(
        coordinate,
        SnykPackageIssuesResult.Status.FAILED,
        List.of(),
        List.of("Snyk package issue query failed"));
  }

  private static FindingSourceObservation observation(
      final Map<ArtifactCoordinate, SnykPackageIssuesResult> results) {
    final long successfulQueries =
        results.values().stream().filter(value -> value.status() != FAILED).count();
    final boolean incomplete =
        results.values().stream().anyMatch(value -> value.status() != COMPLETE);
    final int contributionCount =
        results.values().stream().mapToInt(value -> value.contributions().size()).sum();
    final List<String> queryDiagnostics =
        results.values().stream()
            .filter(value -> value.status() != COMPLETE)
            .flatMap(
                value -> {
                  final List<String> reasons =
                      value.diagnostics().stream()
                          .map(SnykPackageIssuesIntegration::safeDiagnostic)
                          .toList();
                  final List<String> observedReasons =
                      reasons.isEmpty() ? List.of("incomplete package issue response") : reasons;
                  return observedReasons.stream()
                      .map(
                          reason ->
                              "Snyk query "
                                  + value.status().name().toLowerCase(java.util.Locale.ROOT)
                                  + " for "
                                  + value.coordinate().toId()
                                  + ": "
                                  + reason);
                })
            .sorted()
            .toList();
    if (successfulQueries == 0) {
      return new FindingSourceObservation(
          Optional.of(FindingSource.SNYK),
          FindingSourceObservation.Status.ERROR,
          null,
          null,
          "Snyk package issue queries failed for all candidate artifacts",
          queryDiagnostics,
          contributionCount);
    }
    final FindingSourceObservation.Status status =
        incomplete
            ? FindingSourceObservation.Status.PARTIAL
            : FindingSourceObservation.Status.CURRENT;
    final String revision = queryDigest(results);
    final String diagnostic =
        incomplete ? "One or more Snyk package issue queries were incomplete" : null;
    return new FindingSourceObservation(
        Optional.of(FindingSource.SNYK),
        status,
        revision,
        Instant.now(),
        diagnostic,
        queryDiagnostics,
        contributionCount);
  }

  private static String queryDigest(
      final Map<ArtifactCoordinate, SnykPackageIssuesResult> results) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      final List<ArtifactCoordinate> coordinates = new ArrayList<>(results.keySet());
      coordinates.sort(Comparator.naturalOrder());
      for (final ArtifactCoordinate coordinate : coordinates) {
        final SnykPackageIssuesResult result = results.get(coordinate);
        update(digest, coordinate.toId());
        update(digest, result.status().name());
        update(digest, FindingContributionJsonCodec.encode(result.contributions()).toString());
        result.diagnostics().stream().sorted().forEach(value -> update(digest, value));
      }
      return HexFormat.of().formatHex(digest.digest());
    } catch (final NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String safeDiagnostic(final String diagnostic) {
    if (diagnostic.matches("Snyk request failed with HTTP status [1-5][0-9]{2}")) {
      return diagnostic;
    }
    if (Set.of(
            "Snyk authorization token is invalid",
            "Snyk package query requires an exact version",
            "Snyk package query requires Maven group and artifact identifiers",
            "Snyk package query does not support this Maven type or classifier",
            "Snyk request could not be completed",
            "Snyk request was interrupted",
            "Snyk response did not identify the requested package version",
            "Snyk response did not contain an issue list",
            "Snyk pagination link was invalid",
            "Snyk pagination repeated a page")
        .contains(diagnostic)) {
      return diagnostic;
    }
    if (diagnostic.matches(
        "Snyk issue row [1-9][0-9]* (was malformed|had an unsupported issue type)")) {
      return diagnostic;
    }
    return "Snyk package issue query returned an incomplete response";
  }

  private static void update(final MessageDigest digest, final String value) {
    digest.update(value.getBytes(StandardCharsets.UTF_8));
    digest.update((byte) 0);
  }
}
