/* WHY: Verifies dynamic-root owner mapping does not retain unrelated archives. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.plugin.ElisionAnalysisModel.DynamicRootInputs;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks recognized and unresolved dynamic roots against the inventory. */
final class DynamicRootOrchestratorTest {
  /** WHY: Provides isolated archive paths for owner mapping. */
  @TempDir private Path temporaryDirectory;

  @SuppressWarnings({
    "PMD.CommentDefaultAccessModifier",
    "PMD.UncommentedEmptyConstructor",
    "PMD.UnnecessaryConstructor"
  })
  DynamicRootOrchestratorTest() {}

  @Test
  void unresolvedExternalRootDoesNotKeepUnrelatedArchives() {
    final ArtifactFileRef knownOwner = artifact("known-owner");
    final ArtifactFileRef unrelatedOwner = artifact("unrelated-owner");
    final DynamicRootInputs roots =
        new DynamicRootInputs(Set.of("fixture.Known", "external.Unresolved"), Set.of(), Map.of());
    final ArtifactClassIndex index =
        new ArtifactClassIndex(
            Map.of(knownOwner, Set.of("fixture.Known"), unrelatedOwner, Set.of("fixture.Other")));

    final Set<ArtifactCoordinate> owners =
        DynamicRootOrchestrator.dynamicRootArtifactOwners(roots, index);

    assertAll(
        "unresolved external dynamic root keeps only the known owner archive",
        () -> assertThat(owners).contains(knownOwner.coordinate()),
        () -> assertThat(owners).doesNotContain(unrelatedOwner.coordinate()));
  }

  private ArtifactFileRef artifact(final String artifactId) {
    return new ArtifactFileRef(
        ArtifactCoordinate.of("fixture", artifactId, "1.0"),
        temporaryDirectory.resolve(artifactId + ".jar"),
        0,
        0);
  }
}
