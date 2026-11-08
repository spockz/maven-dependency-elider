/* WHY: Defines the final-proof fields that determine whether VEX evidence conflicts. */

package io.github.spockz.elider.metadata;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import io.github.spockz.elider.model.VexAttestation;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Set;

record PreconditionEvidenceIdentity(
    ArtifactCoordinate candidate,
    String justification,
    Set<PrerequisiteClaim> requiredPrerequisites,
    Set<PrerequisiteGroup> groups,
    Set<PrerequisiteMemberObservation> memberObservations,
    Path affectedArtifactPath,
    String postElisionSha256,
    String inventorySha256) {
  PreconditionEvidenceIdentity {
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(justification, "justification");
    requiredPrerequisites = Set.copyOf(requiredPrerequisites);
    groups = Set.copyOf(groups);
    memberObservations = Set.copyOf(memberObservations);
  }

  /* package */ static PreconditionEvidenceIdentity from(final VexAttestation attestation) {
    return new PreconditionEvidenceIdentity(
        attestation.coordinate(),
        attestation.justification(),
        attestation.requiredPrerequisites(),
        attestation.requiredPrerequisiteGroups(),
        attestation.requiredPrerequisiteObservations(),
        attestation.affectedArtifactPath(),
        attestation.postElisionSha256(),
        attestation.inventorySha256());
  }
}
