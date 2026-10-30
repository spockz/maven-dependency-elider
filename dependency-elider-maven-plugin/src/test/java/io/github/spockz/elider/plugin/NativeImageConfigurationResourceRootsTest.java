/* WHY: Verifies exact classpath resource-root lookup and failure boundaries. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises classpath-root option boundaries and providers. */
/* package */ final class NativeImageConfigurationResourceRootsTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** Identifies the archive that declares each resource-root option. */
  private final String declaringArtifact;

  /* package */ NativeImageConfigurationResourceRootsTest() {
    super();
    declaringArtifact = "declaring";
  }

  /* package */
  @Test
  void readsEveryProviderWithoutDirectoryEntriesOrPrefixCollisions() throws IOException {
    final Path declaring =
        declaringJar("-H:ConfigurationResourceRoots=META-INF/native-image/config\n");
    final Path firstProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "root-provider-a.jar",
            "META-INF/native-image/config/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.First"),
            "META-INF/native-image/configx/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.WrongPrefix"));
    final Path secondProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "root-provider-b.jar",
            "META-INF/native-image/config/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Second"));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                candidate(declaringArtifact, declaring),
                candidate("provider-a", firstProvider),
                candidate("provider-b", secondProvider)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);

    NativeImageConfigurationDirectoriesTestSupport.assertResourceRootScan(
        scan, firstProvider, secondProvider);
  }

  /* package */
  @Test
  void ordinaryResourcesEstablishRoot() throws IOException {
    final Path declaring =
        declaringJar("-H:ConfigurationResourceRoots=META-INF/native-image/empty\n");
    final Path marker =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "empty-root-provider.jar",
            "META-INF/native-image/empty/marker.txt",
            "present");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring), candidate("marker", marker)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);
    NativeImageConfigurationDirectoriesTestSupport.assertEmptyResourceRoot(scan);
  }

  /* package */
  @Test
  void missingResourceRootFailsClearly() throws IOException {
    final Path declaring = declaringJar("-H:ConfigurationResourceRoots=absent\n");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring)), temporaryDirectory);
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(declaring, context, Set.of(), true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("resource root is missing");
  }

  private Path declaringJar(final String args) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        temporaryDirectory,
        "declaring-" + Math.abs(args.hashCode()) + ".jar",
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + args);
  }

  private ArtifactFileRef candidate(final String artifact, final Path path) throws IOException {
    return NativeImageScanContextTestSupport.candidate(artifact, path);
  }
}
