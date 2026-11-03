// WHY: Applies only exact or explicitly assumed conventional source path mapping.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.SourceClaimPathMatcher;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** Maps structured CNA claims to paths in one sources archive. */
final class SourceCorrespondencePathMapper {
  /** Exactly one archive entry must match each structured source claim. */
  private static final int ONE_MATCH = 1;

  /** Source-root mapping explicitly enabled by the conventional-layout assumption. */
  private static final String CONVENTIONAL_SOURCE_ROOT = "src/main/java/";

  private SourceCorrespondencePathMapper() {}

  /* default */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // The result map is built serially per claim set.
  static Map<String, String> map(
      final List<String> claims,
      final List<String> sourceEntries,
      final boolean conventionalLayoutAssumed)
      throws IOException {
    if (claims == null || claims.isEmpty()) {
      return Map.of();
    }
    final Set<String> available = Set.copyOf(sourceEntries);
    final Map<String, String> mapped = new TreeMap<>();
    for (final String claim : claims) {
      mapOne(claim, available, conventionalLayoutAssumed, mapped);
    }
    return Collections.unmodifiableMap(mapped);
  }

  private static void mapOne(
      final String claim,
      final Set<String> available,
      final boolean conventionalLayoutAssumed,
      final Map<String, String> mapped)
      throws IOException {
    final String normalized = normalize(claim);
    final List<String> matches = new ArrayList<>(2);
    if (available.contains(normalized)) {
      matches.add(normalized);
    }
    addConventionalMatch(normalized, available, conventionalLayoutAssumed, matches);
    if (matches.size() != ONE_MATCH) {
      throw new IOException(
          matches.isEmpty()
              ? "Structured source path is absent from the exact sources archive: " + claim
              : "Structured source path maps ambiguously in the sources archive: " + claim);
    }
    mapped.put(claim, matches.getFirst());
  }

  private static void addConventionalMatch(
      final String normalized,
      final Set<String> available,
      final boolean assumed,
      final List<String> matches) {
    if (assumed && normalized.startsWith(CONVENTIONAL_SOURCE_ROOT)) {
      final String translated = normalized.substring(CONVENTIONAL_SOURCE_ROOT.length());
      if (available.contains(translated) && !matches.contains(translated)) {
        matches.add(translated);
      }
    }
  }

  private static String normalize(final String claim) throws IOException {
    if (!SourceClaimPathMatcher.isSupportedJavaSourceClaim(claim)) {
      throw new IOException("Unsupported structured Java source path: " + claim);
    }
    final String normalized = claim.replace('\\', '/');
    if (normalized.isBlank()
        || normalized.startsWith("/")
        || java.util.Arrays.stream(normalized.split("/", -1))
            .anyMatch(
                segment -> segment.isBlank() || ".".equals(segment) || "..".equals(segment))) {
      throw new IOException("Unsafe structured source path: " + claim);
    }
    return normalized;
  }
}
