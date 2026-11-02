/* WHY: Verifies target-release selection remains independent of the active JDK class table. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies effective target release interpretation for archive analysis. */
final class TrimPlatformTest {
  /** Release option used by the focused parser cases. */
  private static final String RELEASE_OPTION = "--release";

  @SuppressWarnings({"PMD.UnnecessaryConstructor", "PMD.CommentDefaultAccessModifier"})
  TrimPlatformTest() {
    super();
  }

  @Test
  void targetSelectionUsesTargetDefaultsRuntimeAndRejectsAmbiguity() throws IOException {
    assertAll(
        "effective target release is independent of the active runtime release",
        () ->
            assertThat(
                    TrimPlatform.targetReleaseFromOptions(List.of("-source", "8", "-target", "11")))
                .isEqualTo(11),
        () ->
            assertThat(TrimPlatform.targetReleaseFromOptions(List.of("-target", "11")))
                .isEqualTo(11),
        () ->
            assertThat(TrimPlatform.targetReleaseFromOptions(List.of(RELEASE_OPTION, "1.8")))
                .isEqualTo(8),
        () ->
            assertThat(TrimPlatform.targetReleaseFromOptions(List.of()))
                .isEqualTo(Runtime.version().feature()),
        () ->
            assertThatThrownBy(
                    () ->
                        TrimPlatform.targetReleaseFromOptions(
                            List.of(RELEASE_OPTION, "17", "-source", "17", "-target", "17")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("both release and source/target"),
        () ->
            assertThat(TrimPlatform.targetReleaseFromOptions(List.of("-source", "8")))
                .isEqualTo(Runtime.version().feature()),
        () ->
            assertThatThrownBy(
                    () ->
                        TrimPlatform.targetReleaseFromOptions(
                            List.of(RELEASE_OPTION, "not-a-release")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Unsupported Java compiler release"),
        () ->
            assertThatThrownBy(
                    () -> TrimPlatform.targetReleaseFromOptions(List.of(RELEASE_OPTION, "7")))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("Unsupported Java compiler release"));
  }
}
