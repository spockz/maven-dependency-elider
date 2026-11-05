// WHY: Retains source metadata and artifact bindings in standard VEX detail fields.

package io.github.spockz.elider.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.VexAttestation;
import java.io.IOException;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/** Adds bounded provenance to the standard human-readable VEX detail field. */
final class VexProofDetailFormatter {
  /** Serializes provenance with stable map ordering. */
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);

  private VexProofDetailFormatter() {}

  /* package */ static String format(final VexAttestation attestation) throws IOException {
    Objects.requireNonNull(attestation, "attestation");
    if (attestation.sourceLabels().isEmpty() && attestation.sourceProvenance().isEmpty()) {
      return attestation.impactDetail();
    }
    final ObjectNode details = JSON.createObjectNode();
    details.set("sourceLabels", JSON.valueToTree(new TreeSet<>(attestation.sourceLabels())));
    final List<AdvisoryProvenance> sources =
        attestation.sourceProvenance().stream()
            .sorted(
                Comparator.comparing(
                    value ->
                        value.origin().name()
                            + "\u0000"
                            + value.sourceRecordId()
                            + "\u0000"
                            + value.sourceUrl()
                            + "\u0000"
                            + value.sourceRecordSha256()))
            .toList();
    details.set("sourceProvenance", JSON.valueToTree(sources));
    if (attestation.inventorySha256() != null) {
      details.put("inventorySha256", attestation.inventorySha256());
      details.put("affectedArtifactSha256", attestation.postElisionSha256());
    } else {
      details.put("originalArtifactSha256", attestation.originalSha256());
      details.put("trimmedArtifactSha256", attestation.trimmedSha256());
    }
    return attestation.impactDetail() + "\nSource metadata: " + JSON.writeValueAsString(details);
  }
}
