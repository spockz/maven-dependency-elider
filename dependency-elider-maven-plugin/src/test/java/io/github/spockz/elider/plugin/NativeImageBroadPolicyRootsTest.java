/* WHY: Verifies every enabled broad Native Image option independently selects indexed classes. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks the audited enabled and disabled broad policies. */
/* package */ final class NativeImageBroadPolicyRootsTest {
  /** Shared entry path for native-image property fixtures. */
  private final String propertyEntry;

  /** Keeps every option spelling isolated in its own candidate inventory. */
  /* package */ @TempDir Path temporaryDirectory;

  /* package */ NativeImageBroadPolicyRootsTest() {
    propertyEntry = NativeImageScanContextTestSupport.PROPERTIES_ENTRY;
  }

  /* package */
  @Test
  void enableAllSecurityServicesShortFormPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "-H:+EnableAllSecurityServices");
  }

  /* package */
  @Test
  void enableAllSecurityServicesLongFormPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "--enable-all-security-services");
  }

  /* package */
  @Test
  void addAllFileSystemProvidersPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "-H:+AddAllFileSystemProviders");
  }

  /* package */
  @Test
  void includeAllLocalesPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "-H:+IncludeAllLocales");
  }

  /* package */
  @Test
  void enableUrlProtocolsPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "-H:EnableURLProtocols=http,https");
  }

  /* package */
  @Test
  void enableUrlProtocolsLongFormPinsIndexedClasses() throws IOException {
    NativeImageBroadPolicyRootsTestSupport.assertBroadRoots(
        temporaryDirectory, propertyEntry, "--enable-url-protocols=jar");
  }

  /* package */
  @Test
  void disabledPoliciesAndSecurityFeatureToggleAddNoRoots() throws IOException {
    final Path provider = NativeImageBroadPolicyRootsTestSupport.provider(temporaryDirectory);
    final Path declaring =
        NativeImageBroadPolicyRootsTestSupport.archive(
            temporaryDirectory,
            propertyEntry,
            "policy-disabled.jar",
            "-H:-EnableAllSecurityServices -H:-AddAllFileSystemProviders "
                + "-H:-IncludeAllLocales -H:-EnableSecurityServicesFeature "
                + "-H:+EnableSecurityServicesFeature -H:DisableURLProtocols=http");
    assertThat(NativeImageBroadPolicyRootsTestSupport.scan(declaring, provider).roots()).isEmpty();
  }
}
