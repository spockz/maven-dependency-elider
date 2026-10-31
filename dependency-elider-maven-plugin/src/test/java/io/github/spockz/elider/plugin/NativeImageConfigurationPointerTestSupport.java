/* WHY: Centralizes explicit-kind fixtures for every audited configuration pointer option. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Test inputs proving pointer options select schemas independently of filenames. */
/* package */ final class NativeImageConfigurationPointerTestSupport {
  /** WHY: Exercises each audited pointer using arbitrary payload filenames. */
  private static final List<PointerCase> POINTER_CASES =
      List.of(
          new PointerCase(
              "-H:ReflectionConfigurationResources", true, NativeImageDescriptorKind.REFLECTION),
          new PointerCase(
              "-H:JNIConfigurationResources", true, NativeImageDescriptorKind.REFLECTION),
          new PointerCase(
              "-H:DynamicProxyConfigurationResources", true, NativeImageDescriptorKind.PROXY),
          new PointerCase(
              "-H:SerializationConfigurationResources",
              true,
              NativeImageDescriptorKind.SERIALIZATION),
          new PointerCase(
              "-H:SerializationDenyConfigurationResources",
              true,
              NativeImageDescriptorKind.SERIALIZATION_DENY),
          new PointerCase(
              "-H:PredefinedClassesConfigurationResources",
              true,
              NativeImageDescriptorKind.PREDEFINED_CLASSES),
          new PointerCase(
              "-H:ResourceConfigurationResources", true, NativeImageDescriptorKind.RESOURCES),
          new PointerCase("-H:ForeignResources", true, NativeImageDescriptorKind.FOREIGN),
          new PointerCase(
              "-H:ObjectInliningConfigurationResources",
              true,
              NativeImageDescriptorKind.OBJECT_INLINING),
          new PointerCase(
              "-H:ReachabilityMetadataResources",
              true,
              NativeImageDescriptorKind.REACHABILITY_METADATA),
          new PointerCase(
              "-H:ReflectionConfigurationFiles", false, NativeImageDescriptorKind.REFLECTION),
          new PointerCase("-H:JNIConfigurationFiles", false, NativeImageDescriptorKind.REFLECTION),
          new PointerCase(
              "-H:DynamicProxyConfigurationFiles", false, NativeImageDescriptorKind.PROXY),
          new PointerCase(
              "-H:SerializationConfigurationFiles", false, NativeImageDescriptorKind.SERIALIZATION),
          new PointerCase(
              "-H:SerializationDenyConfigurationFiles",
              false,
              NativeImageDescriptorKind.SERIALIZATION_DENY),
          new PointerCase(
              "-H:PredefinedClassesConfigurationFiles",
              false,
              NativeImageDescriptorKind.PREDEFINED_CLASSES),
          new PointerCase(
              "-H:ResourceConfigurationFiles", false, NativeImageDescriptorKind.RESOURCES),
          new PointerCase("-H:ForeignConfigurationFiles", false, NativeImageDescriptorKind.FOREIGN),
          new PointerCase(
              "-H:ObjectInliningConfigurationFiles",
              false,
              NativeImageDescriptorKind.OBJECT_INLINING));

  /** WHY: A rootless schema must still parse strictly without inventing class roots. */
  private static final Map<NativeImageDescriptorKind, DescriptorFixture> DESCRIPTORS =
      Map.of(
          NativeImageDescriptorKind.REFLECTION,
          new DescriptorFixture(
              NativeImageScanContextTestSupport.reflection("org.example.ReflectionRoot"),
              Set.of("org.example.ReflectionRoot")),
          NativeImageDescriptorKind.PROXY,
          new DescriptorFixture(
              "[{\"interfaces\":[\"org.example.ProxyRoot\"]}]", Set.of("org.example.ProxyRoot")),
          NativeImageDescriptorKind.SERIALIZATION,
          new DescriptorFixture(
              "{\"types\":[{\"name\":\"org.example.SerializationRoot\"}],"
                  + "\"lambdaCapturingTypes\":[]}",
              Set.of("org.example.SerializationRoot")),
          NativeImageDescriptorKind.SERIALIZATION_DENY,
          new DescriptorFixture("{\"types\":[{\"name\":\"org.example.Denied\"}]}", Set.of()),
          NativeImageDescriptorKind.PREDEFINED_CLASSES,
          new DescriptorFixture("[]", Set.of()),
          NativeImageDescriptorKind.REACHABILITY_METADATA,
          new DescriptorFixture(
              "{\"reflection\":[{\"type\":\"org.example.UnifiedRoot\"}]}",
              Set.of("org.example.UnifiedRoot")),
          NativeImageDescriptorKind.OBJECT_INLINING,
          new DescriptorFixture(
              "{\"value_fields\":{\"org.example.InlinedRoot\":[\"field\"]}}",
              Set.of("org.example.InlinedRoot")),
          NativeImageDescriptorKind.FOREIGN,
          new DescriptorFixture("{\"downcalls\":[{\"descriptor\":\"(int)int\"}]}", Set.of()),
          NativeImageDescriptorKind.RESOURCES,
          new DescriptorFixture("{\"bundles\":[{\"name\":\"org.example.BundleRoot\"}]}", Set.of()));

  private NativeImageConfigurationPointerTestSupport() {
    throw new AssertionError("static fixture holder");
  }

  /* package */ static List<PointerCase> pointerCases() {
    return POINTER_CASES;
  }

  /* package */ static String descriptor(final NativeImageDescriptorKind kind) {
    return DESCRIPTORS.get(kind).json();
  }

  /* package */ static void assertDispatch(
      final DependencyDynamicRoots.RootScan scan,
      final PointerCase pointer,
      final String reference) {
    assertThat(scan.roots())
        .as(
            "option %s dispatches arbitrary filename %s as %s",
            pointer.option(), reference, pointer.kind())
        .containsExactlyInAnyOrderElementsOf(DESCRIPTORS.get(pointer.kind()).roots());
  }

  /* package */ static void assertMutationRejectedBeforePublication(
      final MavenElisionService service,
      final ElisionAnalysisModel.PreparedAnalysis prepared,
      final Path publishedOutputDirectory) {
    assertThatThrownBy(() -> service.finish(prepared))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("content changed");
    assertThat(publishedOutputDirectory).doesNotExist();
  }

  /* package */ static void assertPredefinedResourceScan(
      final DependencyDynamicRoots.RootScan scan, final Path provider) throws IOException {
    assertThat(List.of(scan.roots(), scan.resourceProviders()))
        .containsExactly(
            Set.of("org.example.ResourceGenerated", "org.example.ResourceDependency"),
            Set.of(provider.toRealPath()));
  }

  /* package */ record PointerCase(
      String option, boolean resource, NativeImageDescriptorKind kind) {}

  private record DescriptorFixture(String json, Set<String> roots) {}
}
