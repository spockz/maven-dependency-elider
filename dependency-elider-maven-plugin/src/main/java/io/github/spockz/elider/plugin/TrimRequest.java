/* WHY: Binds Maven inputs to one evidence set and policy so each trim
 * operation uses a consistent analysis view. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CacheProducerIdentity;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Inputs shared by candidate analysis and archive publication. */
record TrimRequest(
    MavenProject project,
    MavenSession session,
    AnalysisEnvironment environment,
    List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
    TrimScanInputs scanInputs,
    Set<ArtifactCoordinate> retainedCoordinates,
    TrimEvidence evidence,
    TrimPolicy policy,
    Optional<CacheProducerIdentity> cacheProducerIdentity) {
  TrimRequest {
    java.util.Objects.requireNonNull(cacheProducerIdentity, "cacheProducerIdentity");
  }

  /* package */ TrimRequest(
      final MavenProject project,
      final MavenSession session,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
      final TrimScanInputs scanInputs,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final TrimEvidence evidence,
      final TrimPolicy policy) {
    this(
        project,
        session,
        null,
        candidates,
        scanInputs,
        retainedCoordinates,
        evidence,
        policy,
        Optional.empty());
  }

  /* package */ TrimRequest(
      final MavenProject project,
      final MavenSession session,
      final List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
      final TrimScanInputs scanInputs,
      final Set<ArtifactCoordinate> retainedCoordinates,
      final TrimEvidence evidence,
      final TrimPolicy policy,
      final Optional<CacheProducerIdentity> cacheProducerIdentity) {
    this(
        project,
        session,
        null,
        candidates,
        scanInputs,
        retainedCoordinates,
        evidence,
        policy,
        cacheProducerIdentity);
  }
}
