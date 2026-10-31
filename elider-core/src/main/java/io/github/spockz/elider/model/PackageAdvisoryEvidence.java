/* WHY: Retains package-level vulnerability scope without implying code-level evidence. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
import java.util.Objects;

/** Package and affected-version advisory with no class or prerequisite claim. */
public record PackageAdvisoryEvidence(AdvisoryScope scope, AdvisoryProvenance provenance)
    implements AdvisoryEvidence {
  /** Requires source provenance for a package-only advisory. */
  public PackageAdvisoryEvidence {
    Objects.requireNonNull(scope, "scope");
    Objects.requireNonNull(provenance, "provenance");
    if (provenance.origin() != EvidenceOrigin.OSV) {
      throw new IllegalArgumentException("Package advisory evidence requires OSV provenance");
    }
  }

  @Override
  public ConfidenceLevel confidenceLabel() {
    return ConfidenceLevel.LOW;
  }
}
