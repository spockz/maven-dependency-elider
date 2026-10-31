/* WHY: Proves broad reachability policies and resource regexes enter scan roots safely. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks broad policies and IncludeResources/ExcludeResources option semantics. */
/* package */ final class NativeImagePolicyRootsTest {
  /** Version shared by synthetic test coordinates and archive manifests. */
  private static final String FIXTURE_VERSION = "1.0";

  /** Shared entry path for native-image property fixtures. */
  private final String propertyEntry;

  /** Keeps each policy fixture isolated from other temporary archive tests. */
  /* package */ @TempDir Path temporaryDirectory;

  /* package */ NativeImagePolicyRootsTest() {
    propertyEntry = NativeImageScanContextTestSupport.PROPERTIES_ENTRY;
  }

  /* package */
  @Test
  void resourceRegexPreservesCommasMatchesDirectoryEntriesAndRootsMrjarClasses()
      throws IOException {
    final Path declaring =
        archive(
            "resource-pattern-declaring.jar",
            "-H:IncludeResources=assets/a,b\\.txt "
                + "-H:IncludeResources=ALL-UNNAMED:assets/a,b\\.txt "
                + "-H:IncludeResources=META-INF/versions/17/org/example/Versioned\\.class "
                + "-H:IncludeResources=assets/matched");
    final Path commaProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory, "comma-provider.jar", "assets/a,b.txt", "comma");
    final Path mrjarProvider = mrjarProvider();
    final Path directoryProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "directory-provider.jar",
            "assets/matched/",
            "",
            "assets/matched/nested/ignored.txt",
            "nested");
    final Path nestedOnlyProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "nested-only-provider.jar",
            "assets/matched/nested/ignored.txt",
            "nested");
    final DependencyDynamicRoots.RootScan scan =
        scan(
            declaring,
            declaring,
            commaProvider,
            mrjarProvider,
            directoryProvider,
            nestedOnlyProvider);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.Versioned"),
            Set.of(
                commaProvider.toAbsolutePath().normalize(),
                mrjarProvider.toAbsolutePath().normalize(),
                directoryProvider.toAbsolutePath().normalize()));
  }

  /* package */
  @Test
  void exclusionsWinForPatternRootsWithoutRemovingIndependentDirectRoots() throws IOException {
    final Path declaring =
        archive(
            "resource-exclusion-declaring.jar",
            "-H:IncludeResources=org/example/Excluded.class "
                + "-H:ExcludeResources=org/example/Excluded.class "
                + "-H:Class=org.example.Direct");
    final Path excludedProvider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "excluded-provider.jar",
            "org/example/Excluded.class",
            "class body");
    final DependencyDynamicRoots.RootScan scan = scan(declaring, declaring, excludedProvider);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(Set.of("org.example.Direct"), Set.of());
  }

  /* package */
  @Test
  void malformedRegexAndProtocolInputsFailClearly() throws IOException {
    for (final String argument :
        List.of(
            "-H:IncludeResources=[",
            "-H:IncludeResources=",
            "-H:ExcludeResources=[",
            "-H:ExcludeResources=",
            "-H:EnableURLProtocols=http,,https",
            "-H:DisableURLProtocols=",
            "--enable-url-protocols")) {
      final Path declaring = archive("invalid-policy-" + argument.hashCode() + ".jar", argument);
      assertThatThrownBy(() -> scan(declaring, declaring))
          .as(argument)
          .isInstanceOf(IOException.class);
    }
  }

  /* package */
  @Test
  void namedModuleResourceSelectorMatchesNoClasspathArchives() throws IOException {
    final Path declaring =
        archive("named-module-selector.jar", "-H:IncludeResources=some.module:assets/.*");
    final Path provider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory, "named-selector-provider.jar", "assets/file.txt", "content");
    final DependencyDynamicRoots.RootScan scan = scan(declaring, declaring, provider);

    assertThat(List.of(scan.roots(), scan.resourceProviders())).containsExactly(Set.of(), Set.of());
  }

  /* package */
  @Test
  void exclusionsAcrossArtifactsOverrideIncludesButKeepIndependentRoots() throws IOException {
    final Path includer =
        archive(
            "cross-artifact-includer.jar",
            "-H:IncludeResources=org/example/Excluded.class -H:Class=org.example.Direct");
    final Path excluder =
        archive("cross-artifact-excluder.jar", "-H:ExcludeResources=org/example/Excluded.class");
    final Path provider =
        NativeImageScanContextTestSupport.jar(
            temporaryDirectory,
            "cross-artifact-provider.jar",
            "org/example/Excluded.class",
            "class body");
    final List<ArtifactFileRef> candidates =
        List.of(
            NativeImageScanContextTestSupport.candidate("includer", includer),
            NativeImageScanContextTestSupport.candidate("excluder", excluder),
            NativeImageScanContextTestSupport.candidate("provider", provider));

    final MavenElisionService.DynamicRootInputs roots =
        MavenElisionService.dynamicRoots(candidates);

    assertThat(
            List.of(
                roots.classNames(), roots.declaringArtifacts(), roots.resourceProviderArtifacts()))
        .containsExactly(
            Set.of("org.example.Direct"),
            Set.of(
                ArtifactCoordinate.of("org.example", "includer", FIXTURE_VERSION),
                ArtifactCoordinate.of("org.example", "excluder", FIXTURE_VERSION)),
            Set.of());
  }

  private Path archive(final String name, final String arguments) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        temporaryDirectory, name, propertyEntry, "Args = " + arguments + "\n");
  }

  private Path mrjarProvider() throws IOException {
    final java.util.jar.Manifest manifest = new java.util.jar.Manifest();
    manifest
        .getMainAttributes()
        .put(java.util.jar.Attributes.Name.MANIFEST_VERSION, FIXTURE_VERSION);
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    final Path path = temporaryDirectory.resolve("mrjar-provider.jar");
    try (java.util.jar.JarOutputStream output =
        new java.util.jar.JarOutputStream(java.nio.file.Files.newOutputStream(path), manifest)) {
      output.putNextEntry(
          new java.util.jar.JarEntry("META-INF/versions/17/org/example/Versioned.class"));
      output.write("class body".getBytes(java.nio.charset.StandardCharsets.UTF_8));
      output.closeEntry();
    }
    return path;
  }

  private DependencyDynamicRoots.RootScan scan(final Path declaring, final Path... archives)
      throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (int index = 0; index < archives.length; index++) {
      candidates.add(
          ArtifactFileRef.fromPath(
              ArtifactCoordinate.of("org.example", "policy-" + index, FIXTURE_VERSION),
              archives[index]));
    }
    final NativeImageScanContext context = NativeImageScanContext.create(candidates, null);
    final DependencyDynamicRoots.RootScan raw = DependencyDynamicRoots.scan(declaring, context);
    final Set<String> roots = new HashSet<>(raw.roots());
    final Set<Path> providers = new HashSet<>(raw.resourceProviders());
    final boolean patternRoots =
        NativeImagePolicyRoots.applyResourcePatterns(
            List.of(raw.resourcePatterns()), context, roots, providers);
    return new DependencyDynamicRoots.RootScan(
        roots,
        raw.declaresClassRoots() || patternRoots,
        raw.requiresArtifactRetention(),
        raw.serviceDescriptors(),
        raw.nonServiceRoots(),
        providers,
        raw.consumedInputs(),
        raw.resourcePatterns(),
        raw.serviceLoaderPolicy());
  }
}
