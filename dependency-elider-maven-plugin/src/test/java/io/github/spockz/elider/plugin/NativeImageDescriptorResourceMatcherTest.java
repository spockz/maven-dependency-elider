/* WHY: Verifies pinned Graal glob, module, and deferred descriptor-route semantics. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Exercises deferred resource selectors across archive and file descriptor routes. */
/* package */ final class NativeImageDescriptorResourceMatcherTest
    extends MavenDependencyTrimmerInMemoryClosureSupport {
  /** WHY: Keeps generated archive names unique to this focused test group. */
  private final String fixturePrefix;

  /* package */ NativeImageDescriptorResourceMatcherTest() {
    super();
    fixturePrefix = "matcher";
  }

  /* package */
  @Test
  void globsUsePinnedWildcardGrammarAndRegexSelectorsHonorModules() throws IOException {
    final Path declaring =
        NativeImageDescriptorResourceMatcherTestSupport.propertiesArchive(
            temporaryDirectory,
            fixturePrefix + "-declaring.jar",
            "",
            "META-INF/native-image/test/resource-config.json",
            "{\"resources\":{\"includes\":[{\"pattern\":"
                + "\"ALL-UNNAMED:assets/regex\\\\.dat\"}],\"excludes\":[{\"pattern\":"
                + "\"named.module:assets/regex\\\\.dat\"},{\"pattern\":"
                + "\":assets/regex\\\\.dat\"}]},\"globs\":["
                + "{\"glob\":\"assets/**/selected.dat\"},"
                + "{\"glob\":\"assets/*/one.dat\"},"
                + "{\"glob\":\"assets/empty-module.dat\",\"module\":\"\"},"
                + "{\"glob\":\"assets/literal[1].dat\"},"
                + "{\"glob\":\"assets/**/Only.class\",\"module\":\"ALL-UNNAMED\"}]}");
    final Path direct =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-direct.jar", "assets/selected.dat", "x");
    final Path nested =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-nested.jar", "assets/a/b/selected.dat", "x");
    final Path singleSegment =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-single-segment.jar", "assets/a/one.dat", "x");
    final Path multipleSegments =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-multiple-segments.jar", "assets/a/b/one.dat", "x");
    final Path literal =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-literal.jar", "assets/literal[1].dat", "x");
    final Path nearLiteral =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-near-literal.jar", "assets/literal1.dat", "x");
    final Path regex =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "regex-module.jar", "assets/regex.dat", "x");
    final Path emptyModuleGlob =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "glob-empty-module.jar", "assets/empty-module.dat", "x");
    final Path rootClass =
        NativeImageDescriptorResourceMatcherTestSupport.classArchive(
            temporaryDirectory, "glob-root-class.jar", "assets/Only.class");
    final Path nestedClass =
        NativeImageDescriptorResourceMatcherTestSupport.classArchive(
            temporaryDirectory, "glob-nested-class.jar", "assets/a/Only.class");
    final NativeImageDescriptorResourceMatcherTestSupport.ObservedRoots scan =
        NativeImageDescriptorResourceMatcherTestSupport.scan(
            temporaryDirectory,
            declaring,
            direct,
            nested,
            singleSegment,
            multipleSegments,
            emptyModuleGlob,
            literal,
            nearLiteral,
            regex,
            rootClass,
            nestedClass);

    assertThat(List.of(scan.providers(), scan.roots()))
        .containsExactly(
            Set.of(
                direct.toRealPath(),
                nested.toRealPath(),
                singleSegment.toRealPath(),
                emptyModuleGlob.toRealPath(),
                literal.toRealPath(),
                regex.toRealPath(),
                rootClass.toRealPath(),
                nestedClass.toRealPath()),
            Set.of("assets.Only", "assets.a.Only"));
  }

  /* package */
  @Test
  void standaloneExcludesApplyToGlobsInTheSameDescriptorGroup() throws IOException {
    final Path declaring =
        NativeImageDescriptorResourceMatcherTestSupport.propertiesArchive(
            temporaryDirectory,
            "same-group-declaring.jar",
            "",
            "META-INF/native-image/test/resource-config.json",
            "{\"resources\":{\"includes\":[{\"pattern\":\"never\"}],"
                + "\"excludes\":[{\"pattern\":\"assets/selected\\\\.dat\"}]},"
                + "\"globs\":[{\"glob\":\"assets/**/selected.dat\"}]}");
    final Path provider =
        NativeImageDescriptorResourceMatcherTestSupport.archive(
            temporaryDirectory, "same-group-provider.jar", "assets/selected.dat", "x");
    final NativeImageDescriptorResourceMatcherTestSupport.ObservedRoots scan =
        NativeImageDescriptorResourceMatcherTestSupport.scan(
            temporaryDirectory, declaring, provider);

    assertThat(scan.providers()).isEmpty();
  }

  /* package */
  @Test
  void localizedBundleNamesAreResourceFamiliesRatherThanClassNames() throws IOException {
    final Path declaring =
        NativeImageDescriptorResourceMatcherTestSupport.resourceConfigArchive(
            temporaryDirectory,
            "localized-bundle-declaring.jar",
            "{\"bundles\":[{\"name\":\"org.example.Messages_en-US\"}]}");
    final Path provider =
        NativeImageDescriptorResourceMatcherTestSupport.archiveWithClasses(
            temporaryDirectory,
            "localized-bundle-provider.jar",
            Map.of(
                "org/example/Messages.properties", "base",
                "org/example/MessagesExtra.properties", "near"),
            "org/example/Messages_fr.class");
    final NativeImageDescriptorResourceMatcherTestSupport.ObservedRoots scan =
        NativeImageDescriptorResourceMatcherTestSupport.scan(
            temporaryDirectory, declaring, provider);

    assertThat(List.of(scan.roots(), scan.providers()))
        .containsExactly(Set.of("org.example.Messages_fr"), Set.of(provider.toRealPath()));
  }

  /* package */
  @Test
  void fileDirectoryResourceRootAndUnifiedPointerRoutesResolveSelectors() throws IOException {
    final Path configDirectory = Files.createDirectories(temporaryDirectory.resolve("configs"));
    Files.writeString(
        configDirectory.resolve("resource-config.json"),
        NativeImageDescriptorResourceMatcherTestSupport.patternDocument(
            "routes/directories/Directory\\\\.class"));
    final Path filesDescriptor = temporaryDirectory.resolve("files.payload");
    Files.writeString(
        filesDescriptor,
        NativeImageDescriptorResourceMatcherTestSupport.patternDocument(
            "routes/files/File\\\\.class"));
    final String arguments =
        "-H:ResourceConfigurationFiles=files.payload "
            + "-H:ConfigurationFileDirectories=configs "
            + "-H:ConfigurationResourceRoots=resource-root "
            + "-H:ReachabilityMetadataResources=reach.payload\n";
    final Path declaring =
        NativeImageDescriptorResourceMatcherTestSupport.propertiesArchive(
            temporaryDirectory, "route-declaring.jar", arguments);
    final Path directoryClass =
        NativeImageDescriptorResourceMatcherTestSupport.classArchive(
            temporaryDirectory, "route-directory-class.jar", "routes/directories/Directory.class");
    final Path fileClass =
        NativeImageDescriptorResourceMatcherTestSupport.classArchive(
            temporaryDirectory, "route-file-class.jar", "routes/files/File.class");
    final Path resourceRootDescriptor =
        NativeImageDescriptorResourceMatcherTestSupport.archiveWithClasses(
            temporaryDirectory,
            "route-resource-root.jar",
            Map.of(
                "resource-root/resource-config.json",
                NativeImageDescriptorResourceMatcherTestSupport.patternDocument(
                    "routes/roots/Root\\\\.class")),
            "routes/roots/Root.class");
    final Path reachabilityProvider =
        NativeImageDescriptorResourceMatcherTestSupport.archiveWithClasses(
            temporaryDirectory,
            "route-reachability.jar",
            Map.of("reach.payload", "{\"resources\":[{\"glob\":\"routes/reach/Reach.class\"}]}"),
            "routes/reach/Reach.class");
    final Path unmatched =
        NativeImageDescriptorResourceMatcherTestSupport.classArchive(
            temporaryDirectory, "route-unmatched.jar", "routes/other/Unmatched.class");
    final List<ArtifactFileRef> candidates =
        List.of(
            NativeImageScanContextTestSupport.candidate("declaring", declaring),
            NativeImageScanContextTestSupport.candidate("directory-class", directoryClass),
            NativeImageScanContextTestSupport.candidate("file-class", fileClass),
            NativeImageScanContextTestSupport.candidate("resource-root", resourceRootDescriptor),
            NativeImageScanContextTestSupport.candidate("reachability", reachabilityProvider),
            NativeImageScanContextTestSupport.candidate("unmatched", unmatched));
    final NativeImageScanContext context =
        NativeImageScanContext.create(candidates, temporaryDirectory);
    final DependencyDynamicRoots.RootScan rawScan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);
    final Set<String> selectedRoots = new HashSet<>(rawScan.roots());
    final Set<Path> selectedProviders = new HashSet<>(rawScan.resourceProviders());
    NativeImagePolicyRoots.applyResourcePatterns(
        List.of(rawScan.resourcePatterns()), context, selectedRoots, selectedProviders);

    assertThat(List.of(selectedRoots, selectedProviders))
        .containsExactly(
            Set.of(
                "routes.directories.Directory",
                "routes.files.File",
                "routes.roots.Root",
                "routes.reach.Reach"),
            Set.of(
                directoryClass.toRealPath(),
                fileClass.toRealPath(),
                resourceRootDescriptor.toRealPath(),
                reachabilityProvider.toRealPath()));
  }
}
