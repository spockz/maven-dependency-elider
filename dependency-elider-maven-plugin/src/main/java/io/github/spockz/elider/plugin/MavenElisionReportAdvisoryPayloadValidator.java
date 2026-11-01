// WHY: Dispatches report-only advisory sections without coupling them to proof-row validation.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.Set;

/** Validates the separate advisory review section. */
final class MavenElisionReportAdvisoryPayloadValidator {
  /** Exact section fields for schema version 1. */
  private static final Set<String> SECTION_FIELDS =
      Set.of("packageAdvisories", "heuristicAdvisories");

  private MavenElisionReportAdvisoryPayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode section) throws IOException {
    if (section == null
        || !section.isObject()
        || !MavenElisionReportAdvisoryPayloadSupport.fieldNames(section).equals(SECTION_FIELDS)) {
      throw new IOException("Elision report advisoryReview must match its schema object");
    }
    MavenElisionReportPackageAdvisoryPayloadValidator.validate(section.get("packageAdvisories"));
    MavenElisionReportHeuristicAdvisoryPayloadValidator.validate(
        section.get("heuristicAdvisories"));
    validatePackageOwners(section);
  }

  private static void validatePackageOwners(final JsonNode section) throws IOException {
    final java.util.List<MavenElisionReportAdvisoryInvariants.PackageOwner> packages =
        new java.util.ArrayList<>();
    for (final JsonNode row : section.get("packageAdvisories")) {
      packages.add(
          new MavenElisionReportAdvisoryInvariants.PackageOwner(
              row.get("osvId").textValue(),
              row.get("coordinate").textValue(),
              row.get("ecosystem").textValue(),
              row.get("packageName").textValue(),
              MavenElisionReportAffectedRangePayloadReader.versions(row.get("affectedVersions")),
              MavenElisionReportAffectedRangePayloadReader.ranges(row.get("ranges")),
              OsvPackageApplicability.Status.valueOf(row.get("applicability").textValue())));
    }
    final java.util.List<MavenElisionReportAdvisoryInvariants.HeuristicOwner> heuristics =
        new java.util.ArrayList<>();
    for (final JsonNode row : section.get("heuristicAdvisories")) {
      heuristics.add(
          new MavenElisionReportAdvisoryInvariants.HeuristicOwner(
              row.get("osvId").textValue(),
              row.get("coordinate").textValue(),
              row.get("ecosystem").textValue(),
              row.get("packageName").textValue(),
              OsvPackageApplicability.Status.valueOf(row.get("applicability").textValue())));
    }
    try {
      MavenElisionReportAdvisoryInvariants.validateHeuristicPackageOwners(
          packages, heuristics.stream().distinct().toList());
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }
}
