/* WHY: Proves resource options resolve across the invocation classpath and retain providers. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies invocation-wide classpath resource resolution. */
/* package */ final class NativeImageScanContextTest {
  /* package */
  /** Arbitrary resource name used in option-backed descriptors. */
  private static final String CUSTOM_RESOURCE = "custom.payload";

  /* package */
  /** Shared resource name used to prove duplicate archive scanning. */
  private static final String SHARED_RESOURCE = "shared.payload";

  /** Temporary archive directory. */
  /* package */ @TempDir Path tempDir;

  /** Creates this focused resource-resolution test group. */
  /* package */ NativeImageScanContextTest() {
    super();
  }

  /* package */
  @Test
  void resolvesArbitraryNamedResourceAndRetainsDeclaringAndProviderArchives() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ReflectionConfigurationResources=" + CUSTOM_RESOURCE + "\n"));
    final Path provider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "provider.jar",
            NativeImageScanContextTestSupport.entries(
                CUSTOM_RESOURCE,
                NativeImageScanContextTestSupport.reflection("org.example.FromC")));
    final List<ArtifactFileRef> candidates =
        List.of(
            NativeImageScanContextTestSupport.candidate(
                NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring),
            NativeImageScanContextTestSupport.candidate("provider", provider));

    final MavenElisionService.DynamicRootInputs inputs =
        MavenElisionService.dynamicRoots(candidates);

    assertThat(
            List.of(
                inputs.classNames(),
                inputs.declaringArtifacts(),
                inputs.resourceProviderArtifacts(),
                inputs.scansByPath().get(declaring).resourceProviders()))
        .containsExactly(
            Set.of("org.example.FromC"),
            Set.of(
                NativeImageScanContextTestSupport.candidate(
                        NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring)
                    .coordinate()),
            Set.of(NativeImageScanContextTestSupport.candidate("provider", provider).coordinate()),
            Set.of(provider.toRealPath()));
  }

  /* package */
  @Test
  void parsesEveryDuplicateClasspathResource() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "duplicate-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ReflectionConfigurationResources=" + SHARED_RESOURCE + "\n"));
    final Path firstProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "duplicate-a.jar",
            NativeImageScanContextTestSupport.entries(
                SHARED_RESOURCE,
                NativeImageScanContextTestSupport.reflection("org.example.First")));
    final Path secondProvider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "duplicate-b.jar",
            NativeImageScanContextTestSupport.entries(
                SHARED_RESOURCE,
                NativeImageScanContextTestSupport.reflection("org.example.Second")));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate(
                    NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring),
                NativeImageScanContextTestSupport.candidate("a", firstProvider),
                NativeImageScanContextTestSupport.candidate("b", secondProvider)),
            null);
    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.First", "org.example.Second"),
            Set.of(firstProvider.toRealPath(), secondProvider.toRealPath()));
  }

  /* package */
  @Test
  void rejectsMalformedDuplicateClasspathResource() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "malformed-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ReflectionConfigurationResources=" + SHARED_RESOURCE + "\n"));
    final Path malformed =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "malformed-provider.jar",
            NativeImageScanContextTestSupport.entries(
                SHARED_RESOURCE, NativeImageScanContextTestSupport.MALFORMED_JSON));
    final NativeImageScanContext malformedContext =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate(
                    NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring),
                NativeImageScanContextTestSupport.candidate("bad", malformed)),
            null);
    assertThatThrownBy(
            () -> DependencyDynamicRoots.scan(declaring, malformedContext, Set.of(), true))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(SHARED_RESOURCE);
  }

  /* package */
  @Test
  void descriptorRelativeResourcesStayInDeclaringArchive() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "local-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ReflectionConfigurationResources=${.}/local.payload\n",
                NativeImageScanContextTestSupport.LOCAL_RESOURCE,
                NativeImageScanContextTestSupport.reflection("org.example.Local")));
    final Path other =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "local-other.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.LOCAL_RESOURCE,
                NativeImageScanContextTestSupport.MALFORMED_JSON));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate("declaring", declaring),
                NativeImageScanContextTestSupport.candidate("other", other)),
            null);

    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(Set.of("org.example.Local"), Set.of(declaring.toRealPath()));
  }

  /* package */
  @Test
  void resourceOptionSelectsResourceSchemaForArbitraryArchivePath() throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "resource-kind-declaring.jar",
            NativeImageScanContextTestSupport.entries(
                NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
                "Args = -H:ResourceConfigurationResources=" + CUSTOM_RESOURCE + "\n"));
    final Path provider =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "resource-kind-provider.jar",
            NativeImageScanContextTestSupport.entries(
                CUSTOM_RESOURCE,
                "{\"bundles\":[{\"name\":\"org.example.Bundle\","
                    + "\"classNames\":[\"org.example.BundleClass\"]}]}"));
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate(
                    NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring),
                NativeImageScanContextTestSupport.candidate("provider", provider)),
            null);

    final DependencyDynamicRoots.RootScan scan =
        DependencyDynamicRoots.scan(declaring, context, Set.of(), true);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.Bundle", "org.example.BundleClass"), Set.of(provider.toRealPath()));
  }

  /* package */
  @Test
  void invocationBasePrefersMavenRequestThenFallsBackToProject() {
    final File requestBase = tempDir.resolve("reactor").toFile();
    final File projectBase = tempDir.resolve("module").toFile();

    assertThat(
            List.of(
                Optional.ofNullable(MavenElisionService.invocationBase(requestBase, projectBase)),
                Optional.ofNullable(MavenElisionService.invocationBase(null, projectBase)),
                Optional.ofNullable(MavenElisionService.invocationBase(null, null))))
        .containsExactly(
            Optional.of(requestBase.toPath()), Optional.of(projectBase.toPath()), Optional.empty());
  }
}
