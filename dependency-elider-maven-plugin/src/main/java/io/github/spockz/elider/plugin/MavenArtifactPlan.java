// WHY: Calculates retained Maven views from an effective decision after
// inventory guards pass.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.Analysis;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.ApplyPlan;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.CurrentViews;
import java.io.IOException;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.project.MavenProject;

/** Selects retained artifact views without mutating Maven state. */
final class MavenArtifactPlan {
  private MavenArtifactPlan() {}

  /** Prepares Maven artifact views without mutating project state. */
  /* package */ static ApplyPlan prepare(final MavenProject project, final Analysis analysis)
      throws IOException {
    final Set<MavenArtifactIdentity> elided =
        identities(analysis.effectiveDecision().elidedArtifacts());
    final Set<MavenArtifactIdentity> retained =
        identities(analysis.effectiveDecision().retainedArtifacts());
    retained.retainAll(elided);
    if (!retained.isEmpty()) {
      throw new IOException("Contradictory retained and elided artifact identities: " + retained);
    }
    final CurrentViews currentViews = MavenArtifactInventory.verifyCurrentViews(project, analysis);
    return new ApplyPlan(
        retained(currentViews.resolvedArtifacts(), elided),
        analysis.artifacts().directArtifactsPresent(),
        new LinkedHashSet<>(currentViews.directArtifacts()));
  }

  private static Set<MavenArtifactIdentity> identities(
      final Collection<ArtifactCoordinate> coordinates) {
    final Set<MavenArtifactIdentity> result = new LinkedHashSet<>();
    for (final ArtifactCoordinate coordinate : coordinates) {
      result.add(MavenArtifactIdentity.from(coordinate));
    }
    return result;
  }

  private static Set<Artifact> retained(
      final Collection<Artifact> input, final Set<MavenArtifactIdentity> elided) {
    final Set<Artifact> result = new LinkedHashSet<>();
    for (final Artifact artifact : input) {
      if (!elided.contains(
          MavenArtifactIdentity.from(MavenArtifactInventory.toCoordinate(artifact)))) {
        result.add(artifact);
      }
    }
    return result;
  }
}
