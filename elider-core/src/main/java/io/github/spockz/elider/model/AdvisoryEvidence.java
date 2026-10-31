/* WHY: Keeps proof inputs
 * separate from advisory variants. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;

/** Advisory claim; proof APIs continue to require narrow evidence types. */
public sealed interface AdvisoryEvidence
    permits ExplicitClassMappingEvidence,
        ExplicitPrerequisiteEvidence,
        StructuredSourceClassEvidence,
        CorroboratedSourceClassCandidate,
        HeuristicCandidateEvidence,
        PackageAdvisoryEvidence {
  /** Returns the CVE and exact Maven version scope described by this evidence. */
  AdvisoryScope scope();

  /** Returns source provenance without granting proof authority. */
  AdvisoryProvenance provenance();

  /** Returns the descriptive confidence label associated with this variant. */
  ConfidenceLevel confidenceLabel();
}
