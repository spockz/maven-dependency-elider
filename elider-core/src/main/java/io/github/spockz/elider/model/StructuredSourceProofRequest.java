/* WHY: Carries proof inputs without approval state. */

package io.github.spockz.elider.model;

import java.nio.file.Path;
import java.util.Objects;

/** Inputs rechecked by the core before proof. */
public record StructuredSourceProofRequest(
    String osvId,
    StructuredSourceClassEvidence sourceEvidence,
    ArtifactCoordinate candidate,
    Path cveListGitDir,
    Path advisoryIndex,
    CacheProducerIdentity expectedProducer,
    Path sourcesJar,
    ArtifactCoordinate sourcesCoordinate,
    String sourceRepositoryProvenance,
    boolean conventionalLayoutAssumed) {
  /** Requires source/build inputs; no field is a proof result or class-set approval. */
  public StructuredSourceProofRequest {
    if (osvId == null || osvId.isBlank()) {
      throw new IllegalArgumentException("osvId must be nonblank");
    }
    Objects.requireNonNull(sourceEvidence, "sourceEvidence");
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(cveListGitDir, "cveListGitDir");
    Objects.requireNonNull(advisoryIndex, "advisoryIndex");
    Objects.requireNonNull(expectedProducer, "expectedProducer");
    Objects.requireNonNull(sourcesJar, "sourcesJar");
    Objects.requireNonNull(sourcesCoordinate, "sourcesCoordinate");
    if (sourceRepositoryProvenance == null || sourceRepositoryProvenance.isBlank()) {
      throw new IllegalArgumentException("sourceRepositoryProvenance must be nonblank");
    }
  }
}
