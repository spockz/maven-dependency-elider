/* WHY: Parses Maven PURLs once into the coordinate fields used for exact matching. */

package io.github.spockz.elider.model;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

/** Parsed Maven Package-URL identity, retaining optional source constraints. */
public record MavenPackageIdentity(
    String groupId, String artifactId, String version, String type, String classifier) {
  /** Maven PURL type prefix. */
  private static final String PREFIX = "pkg:maven/";

  /** Characters allowed in a decoded Maven coordinate component. */
  private static final Pattern MAVEN_COMPONENT = Pattern.compile("[A-Za-z0-9_.+\\-]+");

  /** Current canonical Maven Central hostname. */
  private static final String CENTRAL_HOST = "repo.maven.apache.org";

  /** Historical Maven Central hostname retained for source identity records. */
  private static final String LEGACY_CENTRAL_HOST = "repo1.maven.org";

  /** Parses only the Maven PURL type and fails closed on unsupported identity fields. */
  public static Optional<MavenPackageIdentity> parse(final String purl) {
    if (!hasSupportedPurlPrefix(purl)) {
      return Optional.empty();
    }
    return parseMavenPath(purl);
  }

  private static Optional<MavenPackageIdentity> parseMavenPath(final String purl) {
    final int queryIndex = purl.indexOf('?');
    final String path =
        purl.substring(PREFIX.length(), queryIndex < 0 ? purl.length() : queryIndex);
    final Optional<PurlCoordinates> coordinates = parsePath(path);
    if (coordinates.isEmpty()) {
      return Optional.empty();
    }
    final Optional<Map<String, String>> qualifiers =
        queryIndex < 0 ? Optional.of(Map.of()) : parseQualifiers(purl.substring(queryIndex + 1));
    if (qualifiers.isEmpty()) {
      return Optional.empty();
    }
    final Map<String, String> values = qualifiers.orElseThrow();
    final String type = values.getOrDefault("type", "jar");
    final String classifier = values.getOrDefault("classifier", "");
    if (!isMavenComponent(type) || (!classifier.isEmpty() && !isMavenComponent(classifier))) {
      return Optional.empty();
    }
    final PurlCoordinates parsed = coordinates.orElseThrow();
    return Optional.of(
        new MavenPackageIdentity(
            parsed.groupId(), parsed.artifactId(), parsed.version(), type, classifier));
  }

  private static Optional<PurlCoordinates> parsePath(final String path) {
    final String[] parts = path.split("/", -1);
    if (parts.length != 2 || parts[0].isBlank() || parts[1].isBlank()) {
      return Optional.empty();
    }
    final String groupId = decode(parts[0]);
    final Optional<ArtifactVersion> artifact = parseArtifactVersion(parts[1]);
    if (!isMavenComponent(groupId) || artifact.isEmpty()) {
      return Optional.empty();
    }
    final ArtifactVersion parsedArtifact = artifact.orElseThrow();
    return Optional.of(
        new PurlCoordinates(groupId, parsedArtifact.artifactId(), parsedArtifact.version()));
  }

  private static Optional<ArtifactVersion> parseArtifactVersion(final String part) {
    final int versionIndex = part.lastIndexOf('@');
    if (versionIndex < 0) {
      return createArtifactVersion(part, null);
    }
    return createArtifactVersion(part.substring(0, versionIndex), part.substring(versionIndex + 1));
  }

  private static Optional<ArtifactVersion> createArtifactVersion(
      final String rawArtifact, final String rawVersion) {
    if (rawArtifact.isBlank() || (rawVersion != null && rawVersion.isBlank())) {
      return Optional.empty();
    }
    final String artifactId = decode(rawArtifact);
    final String version = rawVersion == null ? null : decode(rawVersion);
    if (!isMavenComponent(artifactId) || (version != null && version.isBlank())) {
      return Optional.empty();
    }
    return Optional.of(new ArtifactVersion(artifactId, version));
  }

  private record PurlCoordinates(String groupId, String artifactId, String version) {}

  private record ArtifactVersion(String artifactId, String version) {}

  private static boolean hasSupportedPurlPrefix(final String purl) {
    return purl != null && purl.startsWith(PREFIX) && purl.indexOf('#') < 0;
  }

  /** Tests whether this PURL identifies the full coordinate using defined defaults. */
  public boolean matches(final ArtifactCoordinate coordinate) {
    return groupId.equals(coordinate.groupId())
        && artifactId.equals(coordinate.artifactId())
        && (version == null || version.equals(coordinate.version()))
        && type.equals(coordinate.type())
        && classifier.equals(coordinate.classifier());
  }

  /** Matches the package portion when version and artifact variant are bound later. */
  public boolean matchesPackage(final String expectedGroupId, final String expectedArtifactId) {
    return groupId.equals(expectedGroupId) && artifactId.equals(expectedArtifactId);
  }

  /** Matches both available CNA product identities without relying on display names. */
  public static boolean matchesCnaPackage(
      final CveAffectedEntryContext entry, final String groupId, final String artifactId) {
    return matchesPackageUrl(entry, groupId, artifactId)
        && matchesCollectionIdentity(entry, groupId, artifactId)
        && (entry.packageUrl() != null || hasCollectionIdentity(entry));
  }

  /** Matches a product identity and variant represented by an OSV Maven scope. */
  public static boolean matchesCnaScope(
      final CveAffectedEntryContext entry, final ArtifactCoordinate coordinate) {
    if (!matchesCnaPackage(entry, coordinate.groupId(), coordinate.artifactId())) {
      return false;
    }
    if (entry.packageUrl() != null) {
      final MavenPackageIdentity purl = parse(entry.packageUrl()).orElse(null);
      return purl != null
          && purl.type().equals(coordinate.type())
          && purl.classifier().equals(coordinate.classifier());
    }
    return "jar".equals(coordinate.type()) && coordinate.classifier().isEmpty();
  }

  /** Matches the available product identity to one exact Maven artifact variant. */
  public static boolean matchesCnaArtifact(
      final CveAffectedEntryContext entry, final ArtifactCoordinate coordinate) {
    final boolean hasPackageUrl = entry.packageUrl() != null;
    final boolean hasCollectionIdentity = hasCollectionIdentity(entry);
    final boolean purlMatches = packageUrlMatchesArtifact(entry, coordinate);
    final boolean collectionMatches = collectionMatchesArtifact(entry, coordinate);
    if ((hasPackageUrl && !purlMatches) || (hasCollectionIdentity && !collectionMatches)) {
      return false;
    }
    return purlMatches || collectionMatches;
  }

  /** Recognizes Maven Central collection URLs for the packageName identity route. */
  public static boolean isRecognizedMavenCollection(final String collectionUrl) {
    if (collectionUrl == null) {
      return false;
    }
    try {
      final URI uri = URI.create(collectionUrl);
      final String host = uri.getHost();
      final String path = uri.getPath() == null ? "" : uri.getPath().replaceAll("/+$", "");
      return "https".equalsIgnoreCase(uri.getScheme())
          && (CENTRAL_HOST.equalsIgnoreCase(host) || LEGACY_CENTRAL_HOST.equalsIgnoreCase(host))
          && (uri.getPort() < 0 || uri.getPort() == 443)
          && "/maven2".equals(path)
          && uri.getUserInfo() == null
          && uri.getQuery() == null
          && uri.getFragment() == null;
    } catch (final IllegalArgumentException exception) {
      return false;
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Optional<Map<String, String>> parseQualifiers(final String query) {
    if (query.isBlank()) {
      return Optional.empty();
    }
    // This temporary map is confined to one synchronous parser invocation.
    final Map<String, String> result = new TreeMap<>();
    for (final String pair : query.split("&", -1)) {
      final int equals = pair.indexOf('=');
      if (equals <= 0 || equals == pair.length() - 1) {
        return Optional.empty();
      }
      final String key = decode(pair.substring(0, equals));
      final String value = decode(pair.substring(equals + 1));
      if ((!"type".equals(key) && !"classifier".equals(key))
          || value.isBlank()
          || result.putIfAbsent(key, value) != null) {
        return Optional.empty();
      }
    }
    return Optional.of(Map.copyOf(result));
  }

  private static boolean matchesPackageUrl(
      final CveAffectedEntryContext entry, final String groupId, final String artifactId) {
    return entry.packageUrl() == null
        || parse(entry.packageUrl())
            .filter(purl -> purl.matchesPackage(groupId, artifactId))
            .isPresent();
  }

  private static boolean matchesCollectionIdentity(
      final CveAffectedEntryContext entry, final String groupId, final String artifactId) {
    return !hasCollectionIdentity(entry)
        || (entry.packageName() != null
            && isRecognizedMavenCollection(entry.collectionUrl())
            && matchesMavenPackageName(entry.packageName(), groupId, artifactId));
  }

  private static boolean hasCollectionIdentity(final CveAffectedEntryContext entry) {
    return entry.packageName() != null || entry.collectionUrl() != null;
  }

  private static boolean packageUrlMatchesArtifact(
      final CveAffectedEntryContext entry, final ArtifactCoordinate coordinate) {
    return entry.packageUrl() != null
        && parse(entry.packageUrl()).filter(purl -> purl.matches(coordinate)).isPresent();
  }

  private static boolean collectionMatchesArtifact(
      final CveAffectedEntryContext entry, final ArtifactCoordinate coordinate) {
    return hasCollectionIdentity(entry)
        && "jar".equals(coordinate.type())
        && coordinate.classifier().isEmpty()
        && isRecognizedMavenCollection(entry.collectionUrl())
        && matchesMavenPackageName(
            entry.packageName(), coordinate.groupId(), coordinate.artifactId());
  }

  private static String decode(final String component) {
    try {
      return URLDecoder.decode(component.replace("+", "%2B"), StandardCharsets.UTF_8);
    } catch (final IllegalArgumentException exception) {
      return "";
    }
  }

  private static boolean isMavenComponent(final String value) {
    return value != null && MAVEN_COMPONENT.matcher(value).matches();
  }

  private static boolean matchesMavenPackageName(
      final String packageName, final String groupId, final String artifactId) {
    if (packageName == null) {
      return false;
    }
    final int separator = packageName.indexOf(':');
    return separator > 0
        && separator == packageName.lastIndexOf(':')
        && groupId.equals(packageName.substring(0, separator))
        && artifactId.equals(packageName.substring(separator + 1));
  }
}
