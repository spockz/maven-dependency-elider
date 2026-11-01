// WHY: Proves source correspondence identity changes with compiler/platform bytes and rejects
// unsupported compiler runtimes.

package io.github.spockz.elider.correspondence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies the exact JDK image pin and fail-closed correspondence behavior. */
@SuppressWarnings("PMD.AtLeastOneConstructor") // JUnit supplies the test instance lifecycle.
final class SourceJdkIdentityTest {
  /** Stable metadata used only to isolate byte changes in synthetic JDK images. */
  private static final String VENDOR = "test-vendor";

  /** Synthetic runtime descriptor for identity digest tests. */
  private static final String RUNTIME = "21.0.1+1";

  /** Isolates temporary synthetic JDK image files. */
  @TempDir private Path temporaryDirectory;

  @Test
  @SuppressWarnings("PMD.LawOfDemeter") // AssertJ chains retain independent assertion context.
  void identityIncludesDigestsOfLoadedCompilerAndJdkImages() throws IOException {
    final Path javaHome = temporaryDirectory.resolve("image");
    write(javaHome.resolve("jmods/jdk.compiler.jmod"), "compiler image one");
    write(javaHome.resolve("lib/modules"), "platform image");
    write(javaHome.resolve("lib/ct.sym"), "release api image");
    final SourceJdkIdentity.Identity original = identity(javaHome);
    final Path compiler = javaHome.resolve("jmods/jdk.compiler.jmod");
    Files.writeString(compiler, "compiler image two");
    final SourceJdkIdentity.Identity changed = identity(javaHome);

    assertAll(
        () -> assertThat(original.javacClassSha256()).isEqualTo(sha256(new byte[] {7, 8, 9})),
        () ->
            assertThat(original.compilerImageSha256()).isNotEqualTo(changed.compilerImageSha256()),
        () -> assertThat(changed.platformImageSha256()).isEqualTo(original.platformImageSha256()),
        () ->
            assertThat(changed.releaseApiImageSha256()).isEqualTo(original.releaseApiImageSha256()),
        () -> assertThat(SourceJdkIdentity.matchesSupportedImage(original)).isFalse(),
        () -> assertThat(SourceJdkIdentity.requireSupportedIdentity(original).identity()).isEmpty(),
        () ->
            assertThat(SourceJdkIdentity.requireSupportedIdentity(original).refusal())
                .contains("Loaded JDK21 compiler/platform bytes are outside the supported pin"));
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter") // AssertJ chains retain independent assertion context.
  void currentJdkIdentityIncludesLoadedJavacAndPlatformDigests() {
    final SourceJdkIdentity.Resolution result = SourceJdkIdentity.current();
    final SourceJdkIdentity.Identity identity = result.identity().orElseThrow();

    assertAll(
        () -> assertThat(identity.feature()).isEqualTo(21),
        () -> assertThat(identity.compilerModule()).isEqualTo("jdk.compiler"),
        () -> assertThat(identity.javacClassSha256()).hasSize(64),
        () -> assertThat(identity.compilerImageSha256()).hasSize(64),
        () -> assertThat(identity.platformImageSha256()).hasSize(64),
        () -> assertThat(identity.releaseApiImageSha256()).hasSize(64),
        () -> assertThat(SourceJdkIdentity.matchesSupportedImage(identity)).isTrue());
  }

  @Test
  void delimiterBearingRuntimeMetadataCannotInjectPinnedDigestFields() {
    final SourceJdkIdentity.Identity pinned = SourceJdkIdentity.current().identity().orElseThrow();
    final SourceJdkIdentity.Identity injected =
        new SourceJdkIdentity.Identity(
            pinned.feature(),
            pinned.compilerModule(),
            pinned.vendor()
                + ";runtime="
                + pinned.runtimeVersion()
                + ";javacClassSha256="
                + pinned.javacClassSha256(),
            pinned.runtimeVersion(),
            "0".repeat(64),
            pinned.compilerImageSha256(),
            pinned.platformImageSha256(),
            pinned.releaseApiImageSha256());

    final boolean matchesPinnedImage = SourceJdkIdentity.matchesSupportedImage(injected);
    assertAll(
        () ->
            assertFalse(
                matchesPinnedImage, "Delimiter-bearing metadata cannot inject pinned image fields"),
        () ->
            assertThat(SourceJdkIdentity.requireSupportedIdentity(injected).identity()).isEmpty());
  }

  @Test
  void unsupportedFeatureOrCompilerModuleIsRejected() {
    assertAll(
        () ->
            assertThrows(
                IOException.class,
                () ->
                    SourceJdkIdentity.create(
                        22, "jdk.compiler", new byte[] {1}, temporaryDirectory, metadata())),
        () ->
            assertThrows(
                IOException.class,
                () ->
                    SourceJdkIdentity.create(
                        21, "other.compiler", new byte[] {1}, temporaryDirectory, metadata())));
  }

  private Path write(final Path path, final String value) throws IOException {
    Files.createDirectories(path.getParent());
    Files.writeString(path, value);
    return path;
  }

  private SourceJdkIdentity.Identity identity(final Path javaHome) throws IOException {
    return SourceJdkIdentity.create(21, "jdk.compiler", new byte[] {7, 8, 9}, javaHome, metadata());
  }

  private SourceJdkIdentity.RuntimeMetadata metadata() {
    return new SourceJdkIdentity.RuntimeMetadata(VENDOR, RUNTIME);
  }

  private static String sha256(final byte[] bytes) {
    try {
      return java.util.HexFormat.of()
          .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }
}
