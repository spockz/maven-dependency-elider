/* WHY: Keeps Snyk page links bound to one package endpoint and origin. */

package io.github.spockz.elider.scanner;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@SuppressWarnings({"PMD.CommentRequired", "PMD.TooManyMethods"})
final class SnykPackageIssuesPagination {
  private static final int PAGE_LIMIT = 1000;
  private static final String API_VERSION = "2024-06-26";
  private static final Pattern PERCENT_ESCAPE = Pattern.compile("%[0-9a-fA-F]{2}");

  private SnykPackageIssuesPagination() {}

  /* package */ static URI endpointFor(
      final URI apiBaseUri, final String orgId, final ArtifactCoordinate coordinate) {
    final String packageUrl =
        "pkg:maven/"
            + coordinate.groupId()
            + "/"
            + coordinate.artifactId()
            + "@"
            + coordinate.version();
    return URI.create(
        origin(apiBaseUri)
            + "/rest/orgs/"
            + encodePathSegment(orgId)
            + "/packages/"
            + encodePathSegment(packageUrl)
            + "/issues?version="
            + API_VERSION);
  }

  /* package */ static URI firstPage(final URI endpoint) {
    return URI.create(endpoint + "&limit=" + PAGE_LIMIT + "&offset=0");
  }

  /* package */ static Page nextPage(
      final URI endpoint,
      final String rawNextLink,
      final int currentOffset,
      final int rowsReturned) {
    if (rawNextLink == null) {
      return Page.none();
    }
    try {
      final URI resolved = endpoint.resolve(rawNextLink);
      if (!validOriginAndPath(endpoint, resolved)) {
        return Page.invalidPage();
      }
      final Map<String, String> parameters = queryParameters(resolved.getRawQuery());
      final Integer nextOffset = validNextOffset(parameters, currentOffset, rowsReturned);
      if (nextOffset == null) {
        return Page.invalidPage();
      }
      final URI sameEndpoint =
          URI.create(origin(endpoint) + endpoint.getRawPath() + "?" + resolved.getRawQuery());
      return new Page(sameEndpoint, nextOffset, false);
    } catch (final IllegalArgumentException | ArithmeticException exception) {
      return Page.invalidPage();
    }
  }

  private static Integer validNextOffset(
      final Map<String, String> parameters, final int currentOffset, final int rowsReturned) {
    if (!API_VERSION.equals(parameters.get("version")) || !validParameterSet(parameters)) {
      return null;
    }
    final int offset;
    try {
      offset = Integer.parseInt(parameters.get("offset"));
    } catch (final NumberFormatException exception) {
      return null;
    }
    final int expectedOffset = Math.addExact(currentOffset, rowsReturned);
    return offset == expectedOffset && offset > currentOffset ? offset : null;
  }

  private static boolean validParameterSet(final Map<String, String> parameters) {
    if (!parameters.containsKey("offset")
        || parameters.size() < 2
        || parameters.size() > 3
        || !Set.of("version", "offset", "limit").containsAll(parameters.keySet())) {
      return false;
    }
    return !parameters.containsKey("limit") || validLimit(parameters.get("limit"));
  }

  private static boolean validLimit(final String value) {
    try {
      final int limit = Integer.parseInt(value);
      return limit > 0 && limit <= PAGE_LIMIT;
    } catch (final NumberFormatException exception) {
      return false;
    }
  }

  private static boolean validOriginAndPath(final URI endpoint, final URI candidate) {
    if (!sameOrigin(endpoint, candidate)
        || candidate.getRawFragment() != null
        || candidate.getRawUserInfo() != null
        || candidate.getRawPath() == null) {
      return false;
    }
    final String expectedPath = normalizePercentEscapes(endpoint.getRawPath());
    final String candidatePath = normalizePercentEscapes(candidate.getRawPath());
    return expectedPath.equals(candidatePath)
        || (expectedPath.startsWith("/rest/")
            && expectedPath.substring("/rest".length()).equals(candidatePath));
  }

  private static String normalizePercentEscapes(final String path) {
    return PERCENT_ESCAPE.matcher(path).replaceAll(match -> match.group().toUpperCase(Locale.ROOT));
  }

  private static boolean sameOrigin(final URI left, final URI right) {
    return right.getHost() != null
        && left.getScheme().equalsIgnoreCase(right.getScheme())
        && left.getHost().equalsIgnoreCase(right.getHost())
        && effectivePort(left) == effectivePort(right);
  }

  private static int effectivePort(final URI uri) {
    if (uri.getPort() >= 0) {
      return uri.getPort();
    }
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, String> queryParameters(final String rawQuery) {
    if (rawQuery == null || rawQuery.isBlank()) {
      return Map.of();
    }
    final Map<String, String> values = new HashMap<>();
    for (final String pair : rawQuery.split("&")) {
      final int delimiter = pair.indexOf('=');
      if (delimiter <= 0) {
        throw new IllegalArgumentException("pagination query is malformed");
      }
      final String key = decodeQuery(pair.substring(0, delimiter));
      final String value = decodeQuery(pair.substring(delimiter + 1));
      if (values.putIfAbsent(key, value) != null) {
        throw new IllegalArgumentException("pagination query has duplicate parameters");
      }
    }
    return values;
  }

  private static String decodeQuery(final String value) {
    return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  private static String encodePathSegment(final String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String origin(final URI uri) {
    return uri.getScheme() + "://" + uri.getRawAuthority();
  }

  /* package */ record Page(URI uri, int offset, boolean invalid) {
    /* package */ static Page none() {
      return new Page(null, -1, false);
    }

    /* package */ static Page invalidPage() {
      return new Page(null, -1, true);
    }
  }
}
