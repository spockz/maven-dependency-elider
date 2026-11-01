// WHY: Makes Maven's recommended-version syntax exact while honoring explicit range bounds.

package io.github.spockz.elider.applicability;

import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.VulnerabilitySymbolMapping;
import java.io.IOException;
import java.util.List;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;
import org.apache.maven.artifact.versioning.InvalidVersionSpecificationException;
import org.apache.maven.artifact.versioning.VersionRange;

/** Evaluates an advisory version specification against one resolved Maven version. */
@SuppressWarnings("PMD.LawOfDemeter")
public final class MavenVersionRangeMatcher {
  private MavenVersionRangeMatcher() {}

  /** Tests one concrete version against a Maven range. */
  public static boolean includes(final String specification, final String version) {
    final VersionRange range = parse(specification);
    if (range.hasRestrictions()) {
      return range.containsVersion(new DefaultArtifactVersion(version));
    }
    final org.apache.maven.artifact.versioning.ArtifactVersion recommended =
        range.getRecommendedVersion();
    return recommended != null
        && new ComparableVersion(recommended.toString()).compareTo(new ComparableVersion(version))
            == 0;
  }

  /** Parses and validates one Maven version specification. */
  public static void validate(final String specification) {
    parse(specification);
  }

  /** Validates every configured mapping range and identifies its owner on failure. */
  public static void validateMappings(
      final List<VulnerabilitySymbolMapping> mappings, final String source) {
    for (final VulnerabilitySymbolMapping mapping : mappings) {
      try {
        validate(mapping.versionRangeSpec());
      } catch (final IllegalArgumentException exception) {
        throw new IllegalArgumentException(
            "Invalid Maven version range in "
                + source
                + " for "
                + mapping.cveId()
                + " "
                + mapping.affectedCoordinate().toId()
                + ": "
                + mapping.versionRangeSpec(),
            exception);
      }
    }
  }

  /** Validates downloaded mapping ranges and reports malformed input as I/O failure. */
  public static void validateDownloadedMappings(
      final List<VulnerabilitySymbolMapping> mappings, final String source) throws IOException {
    try {
      validateMappings(mappings, source);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  /** Validates projected advisory ranges before a cache document is accepted. */
  public static void validateAdvisoryRecords(
      final List<OsvAdvisoryRecord> records, final String source) throws IOException {
    try {
      records.stream()
          .flatMap(record -> record.evidence().stream())
          .map(evidence -> evidence.scope().versionRangeSpec())
          .distinct()
          .forEach(MavenVersionRangeMatcher::validate);
    } catch (final IllegalArgumentException exception) {
      throw new IOException(
          "Invalid Maven version range in " + source + ": " + exception.getMessage(), exception);
    }
  }

  private static VersionRange parse(final String specification) {
    try {
      return VersionRange.createFromVersionSpec(specification);
    } catch (final InvalidVersionSpecificationException | IllegalArgumentException exception) {
      throw new IllegalArgumentException(
          "Invalid Maven version range '" + specification + "': " + exception.getMessage(),
          exception);
    }
  }
}
