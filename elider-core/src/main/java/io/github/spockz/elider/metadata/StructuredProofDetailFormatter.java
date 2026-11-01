// WHY: Keeps structured proof provenance visible in standard VEX detail fields.

package io.github.spockz.elider.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.StructuredProofProvenance;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/** Adds bounded provenance to the standard human-readable VEX detail field. */
final class StructuredProofDetailFormatter {
  /** Deterministic JSON encoder for the human-readable standard detail fields. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

  private StructuredProofDetailFormatter() {}

  /* default */ static String format(final VexAttestation attestation) throws IOException {
    Objects.requireNonNull(attestation, "attestation");
    final Optional<StructuredProofProvenance> provenance = attestation.structuredProofProvenance();
    if (provenance.isEmpty()) {
      return attestation.impactDetail();
    }
    final ObjectNode record = JSON.createObjectNode();
    record.put("candidate", attestation.coordinate().toString());
    record.put("originalArtifactSha256", attestation.originalSha256());
    record.put("trimmedArtifactSha256", attestation.trimmedSha256());
    record.set("provenance", JSON.valueToTree(provenance.orElseThrow()));
    return attestation.impactDetail()
        + "\nStructured proof scope: class absence for the recorded CNA claims only. "
        + "This does not independently validate vulnerability status or "
        + "CNA declaration completeness. "
        + "OSV source is the configured producer-compatible typed index, not independently "
        + "authenticated upstream.\n"
        + JSON.writeValueAsString(record);
  }
}
