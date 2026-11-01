// WHY: Defines the exact inputs the shared core reproduction engine may inspect.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Inputs for one source reproduction attempt. */
public record SourceReproductionRequest(
    ArtifactCoordinate candidate,
    ArtifactCoordinate sourcesCoordinate,
    Path originalJar,
    Path sourcesJar,
    String sourceRepositoryProvenance,
    List<String> sourceClaims,
    List<String> routineClaims,
    boolean conventionalLayoutAssumed) {
  /** Rejects incomplete or mutable request inputs at the public core boundary. */
  public SourceReproductionRequest {
    Objects.requireNonNull(candidate, "candidate");
    Objects.requireNonNull(sourcesCoordinate, "sourcesCoordinate");
    Objects.requireNonNull(originalJar, "originalJar");
    Objects.requireNonNull(sourcesJar, "sourcesJar");
    if (sourceRepositoryProvenance == null || sourceRepositoryProvenance.isBlank()) {
      throw new IllegalArgumentException("sourceRepositoryProvenance must be nonblank");
    }
    sourceClaims = List.copyOf(sourceClaims);
    routineClaims = List.copyOf(routineClaims);
  }
}
