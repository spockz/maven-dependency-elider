// WHY: Applies the same report-only advisory invariants to typed rows and decoded payloads.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.HeuristicCandidateEvidence;
import io.github.spockz.elider.model.OsvAffectedRange;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Shared validation for package and heuristic report rows. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenElisionReportAdvisoryInvariants {
  /** A unique OSV package owner is required for a definite heuristic status. */
  private static final int UNIQUE_PACKAGE_OWNER = 1;

  private MavenElisionReportAdvisoryInvariants() {}

  static void validatePackageIdentity(
      final String coordinateText, final String ecosystem, final String packageName) {
    final ArtifactCoordinate coordinate =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(coordinateText);
    if (!packageName.equals(coordinate.toShortKey()) || !isMavenEcosystem(ecosystem)) {
      throw new IllegalArgumentException(
          "Elision report package advisory identity conflicts with coordinate");
    }
  }

  static void validateProofRawPackageIdentity(
      final String coordinateText, final String ecosystem, final String packageName) {
    final ArtifactCoordinate coordinate =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(coordinateText);
    if (!packageName.equals(coordinate.toShortKey()) || !isMavenEcosystem(ecosystem)) {
      throw new IllegalArgumentException(
          "Elision report structured proof raw OSV package identity conflicts with coordinate");
    }
  }

  static void validatePackageApplicability(
      final String coordinateText,
      final List<String> affectedVersions,
      final List<MavenElisionReportSnapshot.AffectedRange> ranges,
      final OsvPackageApplicability.Status applicability) {
    final String version =
        MavenElisionReportSourceCoordinateValidator.parseCanonical(coordinateText).version();
    final List<OsvAffectedRange> rawRanges =
        ranges.stream()
            .map(range -> new OsvAffectedRange(range.type(), range.repo(), range.events()))
            .toList();
    final OsvPackageApplicability.Result result =
        OsvPackageApplicability.evaluateClaims(affectedVersions, rawRanges, version);
    if (result.status() != applicability) {
      throw new IllegalArgumentException(
          "Elision report package applicability conflicts with raw OSV claims");
    }
  }

  static void validateHeuristicIdentity(
      final String osvId,
      final List<String> aliases,
      final String cveId,
      final String coordinate,
      final String ecosystem,
      final String packageName,
      final String sourceRecordId,
      final List<String> candidateClasses,
      final List<String> candidateDependencies) {
    validatePackageIdentity(coordinate, ecosystem, packageName);
    final Set<String> owners = new java.util.HashSet<>(aliases);
    owners.add(osvId);
    if (cveId != null && !owners.contains(cveId)) {
      throw new IllegalArgumentException("Heuristic CVE must identify its OSV record or alias");
    }
    final int separator = sourceRecordId.indexOf('#');
    final String sourceOwner =
        separator < 0 ? sourceRecordId : sourceRecordId.substring(0, separator);
    if (!owners.contains(sourceOwner)) {
      throw new IllegalArgumentException("Heuristic source record must identify its OSV owner");
    }
    HeuristicCandidateEvidence.validateCandidateNames(candidateClasses, candidateDependencies);
  }

  private static boolean isMavenEcosystem(final String ecosystem) {
    final String normalized = ecosystem.toLowerCase(Locale.ROOT);
    return "maven".equals(normalized) || normalized.startsWith("maven:");
  }

  static void validateHeuristicPackageOwners(
      final List<PackageOwner> packages, final List<HeuristicOwner> heuristics) {
    for (final HeuristicOwner heuristic : heuristics) {
      final List<PackageOwner> matches =
          packages.stream()
              .filter(
                  value ->
                      value.osvId().equals(heuristic.osvId())
                          && value.coordinate().equals(heuristic.coordinate())
                          && value.ecosystem().equals(heuristic.ecosystem())
                          && value.packageName().equals(heuristic.packageName()))
              .toList();
      if (matches.size() == UNIQUE_PACKAGE_OWNER) {
        if (matches.getFirst().applicability() != heuristic.applicability()) {
          throw new IllegalArgumentException(
              "Heuristic applicability conflicts with its unique OSV package owner");
        }
      } else if (heuristic.applicability() != OsvPackageApplicability.Status.UNRESOLVED) {
        throw new IllegalArgumentException(
            "Heuristic applicability requires one unambiguous OSV package owner");
      }
    }
  }

  record PackageOwner(
      String osvId,
      String coordinate,
      String ecosystem,
      String packageName,
      List<String> affectedVersions,
      List<MavenElisionReportSnapshot.AffectedRange> ranges,
      OsvPackageApplicability.Status applicability) {}

  record HeuristicOwner(
      String osvId,
      String coordinate,
      String ecosystem,
      String packageName,
      OsvPackageApplicability.Status applicability) {}
}
