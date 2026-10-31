/* WHY: Shares indexed policy fixtures without coupling individual option assertions. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/** Builds and scans broad-policy fixtures used by independent option tests. */
/* package */ final class NativeImageBroadPolicyRootsTestSupport {
  /** Version shared by synthetic policy archives. */
  private static final String FIXTURE_VERSION = "1.0";

  private NativeImageBroadPolicyRootsTestSupport() {
    throw new AssertionError("static broad-policy fixture support");
  }

  /* package */
  static void assertBroadRoots(
      final Path directory, final String propertyEntry, final String argument) throws IOException {
    final Path declaring =
        archive(
            directory, propertyEntry, "policy-enabled-" + argument.hashCode() + ".jar", argument);
    final DependencyDynamicRoots.RootScan scan = scan(declaring, provider(directory));

    assertThat(scan.roots())
        .as(argument)
        .containsExactlyInAnyOrder("org.example.First", "org.example.Second");
  }

  /* package */
  static Path archive(
      final Path directory, final String propertyEntry, final String name, final String argument)
      throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory, name, propertyEntry, "Args = " + argument + "\n");
  }

  /* package */
  static Path provider(final Path directory) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory,
        "policy-provider.jar",
        "org/example/First.class",
        "body",
        "org/example/Second.class",
        "body");
  }

  /* package */
  static DependencyDynamicRoots.RootScan scan(final Path declaring, final Path provider)
      throws IOException {
    final List<ArtifactFileRef> candidates =
        List.of(candidate("declaring", declaring), candidate("provider", provider));
    return DependencyDynamicRoots.scan(declaring, NativeImageScanContext.create(candidates, null));
  }

  private static ArtifactFileRef candidate(final String artifactName, final Path archive)
      throws IOException {
    return ArtifactFileRef.fromPath(
        ArtifactCoordinate.of("org.example", artifactName, FIXTURE_VERSION), archive);
  }
}
