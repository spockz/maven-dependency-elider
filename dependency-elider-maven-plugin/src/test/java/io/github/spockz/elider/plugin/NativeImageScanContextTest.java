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
import org.apache.maven.execution.DefaultMavenExecutionRequest;
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

  /** Class entry body is ignored by the logical inventory reader. */
  private static final String CLASS_ENTRY_CONTENT = "bytecode";

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
    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

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
            "z-malformed-provider.jar",
            NativeImageScanContextTestSupport.entries(
                SHARED_RESOURCE, NativeImageScanContextTestSupport.MALFORMED_JSON));
    final Path valid =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "a-valid-provider.jar",
            NativeImageScanContextTestSupport.entries(
                SHARED_RESOURCE,
                NativeImageScanContextTestSupport.reflection("org.example.Valid")));
    final NativeImageScanContext malformedContext =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate(
                    NativeImageScanContextTestSupport.DECLARING_ARTIFACT, declaring),
                NativeImageScanContextTestSupport.candidate("a", valid),
                NativeImageScanContextTestSupport.candidate("bad", malformed)),
            null);
    assertThatThrownBy(() -> DependencyDynamicRoots.scan(declaring, malformedContext))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(SHARED_RESOURCE)
        .hasMessageContaining(malformed.toRealPath().toString());
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

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

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

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(Set.of("org.example.BundleClass"), Set.of(provider.toRealPath()));
  }

  /* package */
  @Test
  void invocationBasePrefersMavenRequestThenFallsBackToProject() {
    final File requestBase = tempDir.resolve("invocation").toFile();
    final File reactorBase = tempDir.resolve("reactor").toFile();
    final File projectBase = tempDir.resolve("module").toFile();
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setBaseDirectory(requestBase);
    request.setMultiModuleProjectDirectory(reactorBase);

    assertThat(
            List.of(
                Optional.ofNullable(MavenElisionService.invocationBase(request, projectBase)),
                Optional.ofNullable(
                    MavenElisionService.invocationBase(
                        new DefaultMavenExecutionRequest(), projectBase)),
                Optional.ofNullable(MavenElisionService.invocationBase(null, null))))
        .containsExactly(
            Optional.of(requestBase.toPath()), Optional.of(projectBase.toPath()), Optional.empty());
  }

  /* package */
  @Test
  void packageTargetsExpandAcrossArchivesAtExactPackageBoundariesAndMrJarTiers()
      throws IOException {
    final Path declaring =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "package-declaring.jar",
            NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
            "Args = --initialize-at-run-time=org.example.pkg "
                + "-H:ClassInitialization=org.example.pkg.deep:build_time "
                + "-H:ClassInitialization=org.example.pkg.versioned:rerun\n",
            "org/example/decl/Entry.class",
            CLASS_ENTRY_CONTENT);
    final Path exactPackageClass =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "package-exact.jar",
            "org/example/pkg.class",
            CLASS_ENTRY_CONTENT,
            "org/example/pkg/Exact.class",
            CLASS_ENTRY_CONTENT);
    final Path descendantPackageClass =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "package-descendant.jar",
            "org/example/pkg/deep/Child.class",
            CLASS_ENTRY_CONTENT,
            "org/example/pkgExtra/Sibling.class",
            CLASS_ENTRY_CONTENT);
    final Path versionedPackageClass =
        NativeImageScanContextTestSupport.jar(
            tempDir,
            "package-versioned.jar",
            "META-INF/versions/17/org/example/pkg/versioned/Mr.class",
            "bytecode");
    final NativeImageScanContext context =
        NativeImageScanContext.create(
            List.of(
                NativeImageScanContextTestSupport.candidate("declaring", declaring),
                NativeImageScanContextTestSupport.candidate("exact", exactPackageClass),
                NativeImageScanContextTestSupport.candidate("descendant", descendantPackageClass),
                NativeImageScanContextTestSupport.candidate("versioned", versionedPackageClass)),
            null);

    final DependencyDynamicRoots.RootScan scan = DependencyDynamicRoots.scan(declaring, context);

    assertThat(scan.roots())
        .containsExactlyInAnyOrder(
            "org.example.pkg",
            "org.example.pkg.Exact",
            "org.example.pkg.deep.Child",
            "org.example.pkg.versioned.Mr");
  }

  /* package */
  @Test
  void wholeInitializationOptionsRootEveryLogicalClass() throws IOException {
    final String[] wholeScopeArguments = {
      "--initialize-at-build-time", "--initialize-at-run-time=", "-H:ClassInitialization=:rerun"
    };
    final Set<String> expected = Set.of("org.example.One", "org.example.Two");
    final List<Set<String>> observed = new java.util.ArrayList<>();
    for (final String argument : wholeScopeArguments) {
      final Path archive =
          NativeImageScanContextTestSupport.jar(
              tempDir,
              "whole-scope-" + argument.replaceAll("[^A-Za-z]", "") + ".jar",
              NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
              "Args = " + argument + "\n",
              "org/example/One.class",
              CLASS_ENTRY_CONTENT,
              "org/example/Two.class",
              CLASS_ENTRY_CONTENT);
      observed.add(DependencyDynamicRoots.scan(archive).roots());
    }

    assertThat(observed).containsExactly(expected, expected, expected);
  }
}
