/* WHY: Verifies exact classpath resource-root lookup and failure boundaries. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
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
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

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
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);
    NativeImageConfigurationDirectoriesTestSupport.assertEmptyResourceRoot(scan);
  }

  /* package */
  @Test
  void missingResourceRootFailsClearly() throws IOException {
    final Path declaring = declaringJar("-H:ConfigurationResourceRoots=absent\n");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring)), temporaryDirectory);
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(declaring, context))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("resource root is missing");
  }

  /* package */
  @Test
  void normalizesClasspathRootSeparatorsAndCurrentDirectorySegments() throws IOException {
    final Path declaring =
        declaringJar("-H:ConfigurationResourceRoots=/,./configs,/configs/,configs//./\n");
    final Path provider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "normalized-root-provider.jar",
            "configs/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Config"),
            "other/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Other"));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring), candidate("provider", provider)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.Config", "org.example.Other"), Set.of(provider.toRealPath()));
  }

  /* package */
  @Test
  void emptyNormalizedClasspathRootAllowsEmptyCandidateInventory() throws IOException {
    final Path declaring = declaringJar("-H:ConfigurationResourceRoots=/\n");
    final NativeImageScanContext context =
        NativeImageScanContext.create(List.of(), temporaryDirectory);

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    NativeImageConfigurationDirectoriesTestSupport.assertEmptyResourceRoot(scan);
  }

  /* package */
  @Test
  void rejectsParentSegmentInResourceRoot() throws IOException {
    final Path declaring = declaringJar("-H:ConfigurationResourceRoots=../escape\n");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring)), temporaryDirectory);
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(declaring, context))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image configuration resource root");
  }

  /* package */
  @Test
  void rejectsBackslashInResourceRoot() throws IOException {
    final Path declaring = declaringJar("-H:ConfigurationResourceRoots=folder\\\\escape\n");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(candidate(declaringArtifact, declaring)), temporaryDirectory);
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(declaring, context))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Unsupported native-image configuration resource root");
  }

  /* package */
  @Test
  void expandsDescriptorRelativeRootAcrossExactClasspathPrefix() throws IOException {
    final Path declaring =
        declaringJar(
            "-H:ConfigurationResourceRoots=${.}/configs,${.}/configs/${.},${.}-extra,${.}${.}\n");
    final Path exactProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "relative-root-provider.jar",
            "META-INF/native-image/test/configs/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Relative"),
            "META-INF/native-image/test/configs/META-INF/native-image/test/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Repeated"));
    final Path suffixProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "relative-root-suffix-provider.jar",
            "META-INF/native-image/test-extra/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.HyphenSuffix"),
            "META-INF/native-image/testMETA-INF/native-image/test/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Adjacent"),
            "META-INF/native-image/test/configs-extra/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Suffix"),
            "unrelated/META-INF/native-image/test/configs/reflect-config.json",
            NativeImageScanContextTestSupport.reflection("org.example.Unrelated"));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                candidate(declaringArtifact, declaring),
                candidate("exact-provider", exactProvider),
                candidate("suffix-provider", suffixProvider)),
            temporaryDirectory);
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    NativeImageConfigurationDirectoriesTestSupport.assertDescriptorRelativeRootScan(
        scan, exactProvider, suffixProvider);
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
