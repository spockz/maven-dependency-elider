// WHY: Verifies the production Mojo publishes live structured claims and bounded VEX provenance.

package io.github.spockz.elider.plugin;

import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.correspondence.SourceReproductionEngine;
import java.io.IOException;
import java.nio.file.Path;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the real resolver-to-publication transaction with structured claims. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class MavenStructuredProofPublicationTest {
  /** Isolated project root for the publication fixture. */
  @TempDir private Path temporaryDirectory;

  /** Runs the production publisher and inspects every generated output. */
  @Test
  void mojoPublishesLiveFileAndRoutineProofThroughTheConfiguredSourceResolver()
      throws IOException,
          ReflectiveOperationException,
          MojoExecutionException,
          MojoFailureException {
    Assumptions.assumeTrue(
        SourceReproductionEngine.isSupportedJdk(),
        "Skipping source reproduction structured proof on non-pinned JDK");
    final MavenStructuredProofPublicationScenario.PublishedResult result =
        MavenStructuredProofPublicationScenario.publish(temporaryDirectory);

    assertAll(
        "ElideMojo resolves exact sources and publishes verified claims atomically",
        () -> MavenStructuredProofPublicationAssertions.assertSourceResolverWasUsed(result),
        () -> MavenStructuredProofPublicationAssertions.assertSyntheticCve(result),
        () -> MavenStructuredProofPublicationAssertions.assertSavedReport(result),
        () -> MavenStructuredProofPublicationOutputAssertions.assertVexDocuments(result.paths()),
        () -> MavenStructuredProofPublicationOutputAssertions.assertOutputManifest(result.paths()));
  }
}
