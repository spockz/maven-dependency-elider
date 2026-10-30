/* WHY: Binds Maven inputs to one evidence set and policy so each trim
 * operation uses a consistent analysis view. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Set;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;

/** Inputs shared by candidate analysis and archive publication. */
record TrimRequest(
    MavenProject project,
    MavenSession session,
    List<ElisionAnalysisModel.ArtifactSnapshot> candidates,
    TrimScanInputs scanInputs,
    Set<ArtifactCoordinate> retainedCoordinates,
    TrimEvidence evidence,
    TrimPolicy policy) {}
