/* WHY: Keeps skipped artifacts and their reasons together so analysis and
 * publication apply the same policy. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.util.List;
import java.util.Set;

/** Keeps retained artifacts and pass-through reasons bound together. */
record TrimPassThroughPlan(
    List<ElisionAnalysisModel.ArtifactSnapshot> retainedLibraries,
    List<ElisionAnalysisModel.ArtifactSnapshot> retained,
    Set<String> multiReleaseIdentities,
    Set<String> moduleInfoIdentities,
    Set<String> skippedArtifactIdentities,
    List<ArtifactCoordinate> multiReleaseCoordinates,
    List<ArtifactCoordinate> moduleInfoCoordinates,
    List<ArtifactCoordinate> configuredCoordinates) {}
