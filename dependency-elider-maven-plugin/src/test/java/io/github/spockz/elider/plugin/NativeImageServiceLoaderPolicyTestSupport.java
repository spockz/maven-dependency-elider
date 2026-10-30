/* WHY: Reuses invocation-wide SPI archive arrangements across option semantics tests. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** Builds tiny service archives and validates malformed option forms. */
/* package */ final class NativeImageServiceLoaderPolicyTestSupport {
  /** Service descriptor name shared by the fixtures. */
  /* package */ static final String SERVICE = "org.example.spi.Service";

  /** Provider class shared by the fixtures. */
  /* package */ static final String PROVIDER = "org.example.spi.Provider";

  private NativeImageServiceLoaderPolicyTestSupport() {
    throw new AssertionError("static service-loader test support");
  }

  /* package */ static Path archive(final Path directory, final String name, final String argument)
      throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory,
        name,
        NativeImageScanContextTestSupport.PROPERTIES_ENTRY,
        "Args = " + argument + "\n");
  }

  /* package */ static Path serviceArchive(final Path directory) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory,
        "descriptor.jar",
        "META-INF/services/" + SERVICE,
        PROVIDER + "\n",
        "org/example/spi/Service.class",
        "body");
  }

  /* package */ static Path providerArchive(final Path directory) throws IOException {
    return NativeImageScanContextTestSupport.jar(
        directory, "provider.jar", "org/example/spi/Provider.class", "body");
  }

  /* package */ static List<ArtifactFileRef> candidates(final Path... paths) throws IOException {
    final List<ArtifactFileRef> candidates = new ArrayList<>();
    for (int index = 0; index < paths.length; index++) {
      candidates.add(NativeImageScanContextTestSupport.candidate("spi-" + index, paths[index]));
    }
    return List.copyOf(candidates);
  }

  /* package */ static List<ArtifactFileRef> reversed(final List<ArtifactFileRef> candidates) {
    final List<ArtifactFileRef> reversed = new ArrayList<>(candidates);
    Collections.reverse(reversed);
    return List.copyOf(reversed);
  }

  /* package */ static MavenElisionService.DynamicRootInputs scan(
      final List<ArtifactFileRef> candidates, final boolean conservativeFallback)
      throws IOException {
    final NativeImageScanContext context = NativeImageScanContext.create(candidates, null);
    return MavenElisionService.dynamicRoots(
        candidates,
        (path, scanContext) -> DependencyDynamicRoots.scan(path, scanContext, Set.of(), true),
        context,
        Set.of(),
        conservativeFallback);
  }

  /* package */ static void checkInvalidForms(final Path directory) throws IOException {
    for (final String argument :
        List.of(
            "-H:UseServiceLoaderFeature",
            "-H:+UseServiceLoaderFeature=",
            "-H:-UseServiceLoaderFeature=",
            "-H:+UseServiceLoaderFeature=invalid",
            "-H:-UseServiceLoaderFeature=invalid",
            "-H:ServiceLoaderFeatureExcludeServices",
            "-H:ServiceLoaderFeatureExcludeServices=",
            "-H:ServiceLoaderFeatureExcludeServices=org.example.Bad-Name",
            "-H:ServiceLoaderFeatureExcludeServiceProviders",
            "-H:ServiceLoaderFeatureExcludeServiceProviders=",
            "-H:ServiceLoaderFeatureExcludeServiceProviders=org.example..Provider")) {
      final Path malformed = archive(directory, "bad-" + argument.hashCode() + ".jar", argument);
      assertThatThrownBy(() -> DependencyDynamicRoots.scan(malformed, Set.of(), false))
          .as(argument)
          .isInstanceOf(IOException.class)
          .hasMessageContaining(expectedDiagnostic(argument));
    }
  }

  private static String expectedDiagnostic(final String argument) {
    if (argument.startsWith("-H:+UseServiceLoaderFeature")
        || argument.startsWith("-H:-UseServiceLoaderFeature")
        || "-H:UseServiceLoaderFeature".equals(argument)) {
      return "Malformed ServiceLoader feature toggle";
    }
    if (argument.endsWith("ExcludeServices") || argument.endsWith("ExcludeServiceProviders")) {
      return "has no value";
    }
    return "Unsupported native-image class name";
  }
}
