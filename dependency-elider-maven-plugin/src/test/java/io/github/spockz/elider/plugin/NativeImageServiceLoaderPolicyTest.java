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

    final ElisionAnalysisModel.DynamicRootInputs forward =
        NativeImageServiceLoaderPolicyTestSupport.scan(candidates, false);
    final ElisionAnalysisModel.DynamicRootInputs reverse =
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
    final Path enabled =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory, "feature-enabled.jar", "-H:+UseServiceLoaderFeature");
    final Path serviceExcluded =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "service-excluded.jar",
            "-H:ServiceLoaderFeatureExcludeServices="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE);
    final Path serviceDirect =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "service-direct.jar",
            "-H:ServiceLoaderFeatureExcludeServices="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE
                + " -H:Class="
                + NativeImageServiceLoaderPolicyTestSupport.SERVICE);
    final Path providerExcluded =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "provider-excluded.jar",
            "-H:ServiceLoaderFeatureExcludeServiceProviders="
                + NativeImageServiceLoaderPolicyTestSupport.PROVIDER);
    final Path providerDirect =
        NativeImageServiceLoaderPolicyTestSupport.archive(
            temporaryDirectory,
            "provider-direct.jar",
            "-H:ServiceLoaderFeatureExcludeServiceProviders="
                + NativeImageServiceLoaderPolicyTestSupport.PROVIDER
                + " -H:Class="
                + NativeImageServiceLoaderPolicyTestSupport.PROVIDER);
    final Path descriptor =
        NativeImageServiceLoaderPolicyTestSupport.serviceArchive(temporaryDirectory);
    final Path provider =
        NativeImageServiceLoaderPolicyTestSupport.providerArchive(temporaryDirectory);
    final List<ArtifactFileRef> serviceCandidates =
        NativeImageServiceLoaderPolicyTestSupport.candidates(
            enabled, serviceExcluded, descriptor, provider);
    final Set<String> serviceFiltered =
        NativeImageServiceLoaderPolicyTestSupport.scan(serviceCandidates, false).classNames();
    final Set<String> serviceFilteredReverse =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.reversed(serviceCandidates), false)
            .classNames();
    final Set<String> serviceDirectRoots =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    enabled, serviceDirect, descriptor, provider),
                false)
            .classNames();
    final Set<String> providerFiltered =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    enabled, providerExcluded, descriptor, provider),
                false)
            .classNames();
    final Set<String> providerDirectRoots =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    enabled, providerDirect, descriptor, provider),
                false)
            .classNames();
    final Set<String> conservativeRoots =
        NativeImageServiceLoaderPolicyTestSupport.scan(
                NativeImageServiceLoaderPolicyTestSupport.candidates(
                    enabled, serviceExcluded, descriptor, provider),
                true)
            .classNames();

    assertThat(
            List.of(
                serviceFiltered,
                serviceFilteredReverse,
                serviceDirectRoots,
                providerFiltered,
                providerDirectRoots,
                conservativeRoots))
        .containsExactly(
            Set.of(),
            Set.of(),
            Set.of(NativeImageServiceLoaderPolicyTestSupport.SERVICE),
            Set.of(NativeImageServiceLoaderPolicyTestSupport.SERVICE),
            Set.of(
                NativeImageServiceLoaderPolicyTestSupport.SERVICE,
                NativeImageServiceLoaderPolicyTestSupport.PROVIDER),
            Set.of(
                NativeImageServiceLoaderPolicyTestSupport.SERVICE,
                NativeImageServiceLoaderPolicyTestSupport.PROVIDER));
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
