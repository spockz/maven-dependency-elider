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

  /** Shared JSON field name for the CVE owner. */
  private static final String CVE_ID = "cveId";

  /** Shared JSON field name for the saved layout assumption. */
  private static final String LAYOUT_ASSUMED = "conventionalLayoutAssumed";

  /** Shared JSON field name for the proof candidate coordinate. */
  private static final String COORDINATE = "coordinate";

  /** Lowercase SHA-256 syntax used by proof archive digest fields. */
  private static final String SHA256_PATTERN = "[0-9a-f]{64}";

  /** Exact fields accepted for a saved proof row. */
  private static final Set<String> FINDING_FIELDS =
      Set.of(CVE_ID, COORDINATE, "originalSha256", "trimmedSha256", "provenance");

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
          LAYOUT_ASSUMED,
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
  static void validate(final JsonNode rows, final boolean snapshotLayoutAssumption)
      throws IOException {
    if (rows == null || !rows.isArray()) {
      throw new IOException("Elision report verifiedStructuredProofs must be an array");
    }
    final Set<ProofIdentity> seen = new HashSet<>();
    for (final JsonNode row : rows) {
      validateFinding(row);
      validateLayoutAssumption(row, snapshotLayoutAssumption);
      if (!seen.add(ProofIdentity.of(row))) {
        throw new IOException(
            "Elision report contains a duplicate verified structured proof identity");
      }
    }
  }

  private record ProofIdentity(String cveId, String coordinate) {
    private static ProofIdentity of(final JsonNode row) {
      return new ProofIdentity(
          row.get(CVE_ID).textValue(),
          MavenElisionReportSourceCoordinateValidator.parseCanonical(
                  row.get("coordinate").textValue())
              .toId());
    }
  }

  private static void validateFinding(final JsonNode row) throws IOException {
    MavenElisionReportJsonPayloadShape.requireObject(
        row, FINDING_FIELDS, "verified structured proof");
    MavenElisionReportJsonPayloadShape.requireText(
        row.get(CVE_ID), CVE_ID, "CVE-[0-9]{4}-[0-9]{4,}");
    MavenElisionReportSourceCoordinateValidator.validate(row.get(COORDINATE));
    MavenElisionReportJsonPayloadShape.requireText(
        row.get("originalSha256"), "originalSha256", SHA256_PATTERN);
    MavenElisionReportJsonPayloadShape.requireText(
        row.get("trimmedSha256"), "trimmedSha256", SHA256_PATTERN);
    final JsonNode provenance = row.get("provenance");
    validateProvenance(provenance);
    final JsonNode rawScope = provenance.get("rawScopeEvidence");
    try {
      MavenElisionReportAdvisoryInvariants.validateProofRawPackageIdentity(
          row.get(COORDINATE).textValue(),
          rawScope.get("osvEcosystem").textValue(),
          rawScope.get("osvPackageName").textValue());
    } catch (final IllegalArgumentException exception) {
      throw new IOException(exception.getMessage(), exception);
    }
  }

  private static void validateLayoutAssumption(
      final JsonNode row, final boolean snapshotLayoutAssumption) throws IOException {
    final boolean proofLayoutAssumption =
        row.path("provenance").path(LAYOUT_ASSUMED).booleanValue();
    if (proofLayoutAssumption != snapshotLayoutAssumption) {
      throw new IOException(
          "Elision report structured proof layout assumption must match the snapshot");
    }
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
    MavenElisionReportJsonPayloadShape.requireBoolean(node.get(LAYOUT_ASSUMED), LAYOUT_ASSUMED);
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
