// WHY: Applies focused field-level mutations to serialized structured proof report fixtures.

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Mutates isolated report payload copies for strict reader tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenStructuredProofReportPayloadMutator {
  /** Saved report collection field containing proof rows. */
  private static final String VERIFIED_PROOFS_FIELD = "verifiedStructuredProofs";

  /** Saved proof field containing provenance. */
  private static final String PROVENANCE_FIELD = "provenance";

  /** JSON mapper used to append one typed source-review row. */
  private static final ObjectMapper JSON = new ObjectMapper();

  private MavenStructuredProofReportPayloadMutator() {}

  /** Adds a duplicate proof row with different source-record provenance. */
  static void appendDuplicateWithDifferentSourceDigest(final JsonNode payload) {
    final ArrayNode proofs = (ArrayNode) payload.get(VERIFIED_PROOFS_FIELD);
    final ObjectNode duplicate = (ObjectNode) proofs.get(0).deepCopy();
    ((ObjectNode) duplicate.get(PROVENANCE_FIELD)).put("cveSourceSha256", "f".repeat(64));
    proofs.add(duplicate);
  }

  /** Changes the saved proof's layout flag. */
  static void changeProofLayoutAssumption(final JsonNode payload, final boolean value) {
    proofProvenance(payload).put("conventionalLayoutAssumed", value);
  }

  /** Changes one raw OSV source field in a proof row. */
  static void changeProofRawScopeText(
      final JsonNode payload, final String field, final String value) {
    ((ObjectNode) proofProvenance(payload).get("rawScopeEvidence")).put(field, value);
  }

  /** Adds one source-review row to a saved report payload. */
  static void appendSourceReviewFinding(
      final JsonNode payload, final MavenElisionReportSnapshot.SourceReviewFinding finding) {
    ((ArrayNode) payload.get("sourceReviewFindings")).add(JSON.valueToTree(finding));
  }

  private static ObjectNode proofProvenance(final JsonNode payload) {
    return (ObjectNode)
        ((ObjectNode) payload.get(VERIFIED_PROOFS_FIELD).get(0)).get(PROVENANCE_FIELD);
  }
}
