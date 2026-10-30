/* WHY: Proves Graal ServiceLoader settings aggregate across archives before roots are selected. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactFileRef;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies invocation-wide ServiceLoader feature roots and exclusions. */
/* package */ final class NativeImageServiceLoaderPolicyTest {
  /** Isolates policy archives for each test. */
  /* package */ @TempDir Path temporaryDirectory;

  /** Service interface name used in root expectations. */
  private final String serviceName;

  /* package */ NativeImageServiceLoaderPolicyTest() {
    serviceName = NativeImageServiceLoaderPolicyTestSupport.SERVICE;
  }

  /* package */
  @Test
  void featureRootsAggregateAcrossArchivesIndependentOfCandidateOrder() throws IOException {
    final Path declaring =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory, "declaring.jar", "-H:+UseServiceLoaderFeature");
    final Path descriptor =
        NativeImageServiceLoaderPolicyTestSupport.serviceArchive(temporaryDirectory);
    final Path provider =
        NativeImageServiceLoaderPolicyTestSupport.providerArchive(temporaryDirectory);
    final List<ArtifactFileRef> candidates =
        NativeImageServiceLoaderPolicyTestSupport.candidates(declaring, descriptor, provider);

    final MavenElisionService.DynamicRootInputs forward =
        NativeImageServiceLoaderPolicyTestSupport.scan(candidates, false);
    final MavenElisionService.DynamicRootInputs reverse =
        NativeImageServiceLoaderPolicyTestSupport.scan(
            NativeImageServiceLoaderPolicyTestSupport.reversed(candidates), false);

    assertThat(List.of(forward.classNames(), reverse.classNames()))
        .containsExactly(
            Set.of(serviceName, NativeImageServiceLoaderPolicyTestSupport.PROVIDER),
            Set.of(serviceName, NativeImageServiceLoaderPolicyTestSupport.PROVIDER));
  }

  /* package */
  @Test
  void featureExclusionsFilterOnlyFeatureRootsAndNeverSubtractDirectRoots() throws IOException {
    final Path serviceExcluded =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "service-excluded.jar",
            "-H:+UseServiceLoaderFeature -H:ServiceLoaderFeatureExcludeServices="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE
                + " -H:Class="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE);
    final Path providerExcluded =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "provider-excluded.jar",
            "-H:+UseServiceLoaderFeature -H:ServiceLoaderFeatureExcludeServiceProviders="
                + NativeImageServiceLoaderPolicyTestSupport.PROVIDER
                + " -H:Class=org.example.Direct");
    final Path descriptor =
        NativeImageServiceLoaderPolicyTestSupport.serviceArchive(temporaryDirectory);
    final Path provider =
        NativeImageServiceLoaderPolicyTestSupport.providerArchive(temporaryDirectory);
    final Set<String> serviceFiltered =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    serviceExcluded, descriptor, provider),
                false)
            .classNames();
    final Set<String> providerFiltered =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    providerExcluded, descriptor, provider),
                false)
            .classNames();

    assertThat(List.of(serviceFiltered, providerFiltered))
        .containsExactly(
            Set.of(NativeImageServiceLoaderPolicyTestSupport.SERVICE),
            Set.of(NativeImageServiceLoaderPolicyTestSupport.SERVICE, "org.example.Direct"));
  }

  /* package */
  @Test
  void exclusionsAndDisabledFeatureAddNoServiceRoots() throws IOException {
    final Path disabled =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory, "disabled.jar", "-H:-UseServiceLoaderFeature");
    final Path excluded =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "excluded.jar",
            "-H:ServiceLoaderFeatureExcludeServices="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE);
    final Path descriptor =
        NativeImageServiceLoaderPolicyTestSupport.serviceArchive(temporaryDirectory);
    final Path provider =
        NativeImageServiceLoaderPolicyTestSupport.providerArchive(temporaryDirectory);
    final List<ArtifactFileRef> disabledCandidates =
        NativeImageServiceLoaderPolicyTestSupport.candidates(disabled, descriptor, provider);
    final List<ArtifactFileRef> excludedCandidates =
        NativeImageServiceLoaderPolicyTestSupport.candidates(excluded, descriptor, provider);

    assertThat(
            List.of(
                NativeImageServiceLoaderPolicyTestSupport.scan(disabledCandidates, false)
                    .classNames(),
                NativeImageServiceLoaderPolicyTestSupport.scan(excludedCandidates, false)
                    .classNames()))
        .containsExactly(Set.of(), Set.of());
  }

  /* package */
  @Test
  void malformedExclusionFormsFail() throws IOException {
    NativeImageServiceLoaderPolicyTestSupport.checkInvalidForms(temporaryDirectory);
  }
}
