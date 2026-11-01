// WHY: Rejects malformed persisted proof provenance before descriptive DTO binding.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/** Validates the saved provenance graph for verified structured proofs. */
final class MavenElisionReportStructuredProofPayloadValidator {
  /** Shared JSON field name for entry type. */
  private static final String TYPE = "type";

  /** Shared JSON field name for the proof candidate coordinate. */
  private static final String COORDINATE = "coordinate";

  /** Lowercase SHA-256 syntax used by proof archive digest fields. */
  private static final String SHA256_PATTERN = "[0-9a-f]{64}";

  /** Exact fields accepted for a saved proof row. */
  private static final Set<String> FINDING_FIELDS =
      Set.of("cveId", COORDINATE, "originalSha256", "trimmedSha256", "provenance");

  /** Exact fields accepted for structured proof provenance. */
  private static final Set<String> PROVENANCE_FIELDS =
      Set.of(
          "osvId",
          "cveSourceSha256",
          "cnaAffectedEntryIdentity",
          "affectedProductIdentity",
          "osvSourceAuthority",
          "sourcesCoordinate",
          "sourcesArchiveSha256",
          "sourceRepositoryProvenance",
          "compilerIdentity",
          "compilerOptions",
          "conventionalLayoutAssumed",
          "rawScopeEvidence",
          "claimAttributions");

  /** Exact fields accepted for a source artifact coordinate. */
  private static final Set<String> COORDINATE_FIELDS =
      Set.of("groupId", "artifactId", "version", TYPE, "classifier", "scope");

  /** Text fields that must identify the current proof owner and source resolution. */
  private static final Set<String> REQUIRED_PROVENANCE_TEXT_FIELDS =
      Set.of(
          "osvId",
          "cnaAffectedEntryIdentity",
          "affectedProductIdentity",
          "sourceRepositoryProvenance",
          "compilerIdentity");

  private MavenElisionReportStructuredProofPayloadValidator() {}

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void validate(final JsonNode rows) throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report verifiedStructuredProofs must be an array");
    }
    final Set<JsonNode> seen = new HashSet<>();
    for (final JsonNode row : rows) {
      validateFinding(row);
      if (!seen.add(row)) {
        throw new IOException("Elision report contains a duplicate verified structured proof");
      }
    }
  }

  private static void validateFinding(final JsonNode row) throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(
        row, FINDING_FIELDS, "verified structured proof");
    MavenElisionReportJsonPayloadShape.requireText(
        row.get("cveId"), "cveId", "CVE-[0-9]{4}-[0-9]{4,}");
    MavenElisionReportSourceCoordinateValidator.validate(row.get(COORDINATE));
    MavenElisionReportJsonPayloadShape.requireText(
        row.get("originalSha256"), "originalSha256", SHA256_PATTERN);
    MavenElisionReportJsonPayloadShape.requireText(
        row.get("trimmedSha256"), "trimmedSha256", SHA256_PATTERN);
    validateProvenance(row.get("provenance"));
  }

  private static void validateProvenance(final JsonNode node) throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(
        node, PROVENANCE_FIELDS, "structured proof provenance");
    for (final String field : REQUIRED_PROVENANCE_TEXT_FIELDS) {
      MavenElisionReportJsonPayloadShape.requireText(node.get(field), field, ".+");
    }
    MavenElisionReportJsonPayloadShape.requireText(
        node.get("cveSourceSha256"), "cveSourceSha256", SHA256_PATTERN);
    MavenElisionReportJsonPayloadShape.requireText(
        node.get("sourcesArchiveSha256"), "sourcesArchiveSha256", SHA256_PATTERN);
    MavenElisionReportJsonPayloadShape.requireText(
        node.get("osvSourceAuthority"),
        "osvSourceAuthority",
        "CONFIGURED_PRODUCER_COMPATIBLE_INDEX");
    MavenElisionReportJsonPayloadShape.stringArray(node.get("compilerOptions"), "compilerOptions");
    MavenElisionReportJsonPayloadShape.requireBoolean(
        node.get("conventionalLayoutAssumed"), "conventionalLayoutAssumed");
    validateCoordinate(node.get("sourcesCoordinate"));
    MavenElisionReportRawScopePayloadValidator.validate(node.get("rawScopeEvidence"));
    final JsonNode claims = node.get("claimAttributions");
    MavenElisionReportJsonPayloadShape.requireArray(claims, "claimAttributions");
    if (claims.isEmpty()) {
      throw new IOException("Elision report claimAttributions must not be empty");
    }
    for (final JsonNode claim : claims) {
      MavenElisionReportClaimPayloadValidator.validate(claim);
    }
  }

  private static void validateCoordinate(final JsonNode node) throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(node, COORDINATE_FIELDS, "source coordinate");
    for (final String field : COORDINATE_FIELDS) {
      MavenElisionReportJsonPayloadShape.requireText(node.get(field), field, ".+");
    }
  }
}
