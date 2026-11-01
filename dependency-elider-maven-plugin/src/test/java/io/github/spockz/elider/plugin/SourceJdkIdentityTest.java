// WHY: Proves source correspondence identity changes with compiler/platform bytes and rejects
// unsupported compiler runtimes.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
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

  /** Synthetic platform name for identity digest tests. */
  private static final String OPERATING_SYSTEM = "test-os";

  /** Synthetic architecture for identity digest tests. */
  private static final String ARCHITECTURE = "test-arch";

  /** Synthetic OS version for identity digest tests. */
  private static final String OS_VERSION = "test-version";

  /** Isolates temporary synthetic JDK image files. */
  @TempDir private Path temporaryDirectory;

  @Test
  @SuppressWarnings("PMD.LawOfDemeter") // AssertJ chains retain independent assertion context.
  void identityIncludesDigestsOfLoadedCompilerAndJdkImages() throws IOException {
    final Path javaHome = temporaryDirectory.resolve("image");
    write(javaHome.resolve("jmods/jdk.compiler.jmod"), "compiler image one");
    write(javaHome.resolve("lib/modules"), "platform image");
    write(javaHome.resolve("lib/ct.sym"), "release api image");
    final String original = identity(javaHome);
    final Path compiler = javaHome.resolve("jmods/jdk.compiler.jmod");
    Files.writeString(compiler, "compiler image two");
    final String changed = identity(javaHome);

    assertAll(
        () ->
            assertThat(original)
                .contains("javacClassSha256=", "compilerImageSha256=", "platformImageSha256=")
                .contains("releaseApiImageSha256="),
        () -> assertThat(changed).isNotEqualTo(original),
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
    final String identity = result.identity().orElseThrow();

    assertAll(
        () ->
            assertThat(identity)
                .contains("feature=21", "module=jdk.compiler", "javacClassSha256=")
                .contains("compilerImageSha256=", "platformImageSha256=", "releaseApiImageSha256="),
        () -> assertThat(SourceJdkIdentity.matchesSupportedImage(identity)).isTrue());
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

  private String identity(final Path javaHome) throws IOException {
    return SourceJdkIdentity.create(21, "jdk.compiler", new byte[] {7, 8, 9}, javaHome, metadata());
  }

  private SourceJdkIdentity.RuntimeMetadata metadata() {
    return new SourceJdkIdentity.RuntimeMetadata(
        VENDOR, RUNTIME, OPERATING_SYSTEM, ARCHITECTURE, OS_VERSION);
  }
}
