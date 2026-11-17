/* WHY: Defines byte-preserving outcomes for global service-provider reconciliation. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Covers unchanged, rewritten, omitted, and malformed root service descriptors. */
final class ServiceDescriptorFilterTest {
  /** Absent provider class name shared across descriptor reconciliation tests. */
  private static final String KNOWN_DEAD = "known.Dead";

  @SuppressWarnings("PMD.UnnecessaryConstructor")
  /* default */ ServiceDescriptorFilterTest() {
    // WHY: PMD requires an explicit package-private JUnit constructor here.
  }

  @Test
  void unchangedPreservesDescriptorBytesExactly() throws IOException {
    final String liveProvider = "known.Live";
    final byte[] original =
        ("# keep this comment\r\nunknown.Provider  \n" + liveProvider + "\r")
            .getBytes(StandardCharsets.UTF_8);

    final ServiceDescriptorFilter.Result result =
        ServiceDescriptorFilter.reconcile(original, Set.of(liveProvider), Set.of(liveProvider));

    assertAll(
        "Service descriptor remains unchanged when all known providers are retained",
        () -> assertThat(result.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.UNCHANGED),
        () -> assertThat(result.bytes()).containsExactly(original));
  }

  @Test
  void replacementRemovesOnlyKnownAbsentProvidersAndPreservesOtherLines() throws IOException {
    final byte[] original =
        ("# retain comment\r\n"
                + "known.Dead # removed\r\n"
                + "unknown.External  \n"
                + "known.Live\r")
            .getBytes(StandardCharsets.UTF_8);
    final byte[] expected =
        "# retain comment\r\nunknown.External  \nknown.Live\r".getBytes(StandardCharsets.UTF_8);

    final ServiceDescriptorFilter.Result result =
        ServiceDescriptorFilter.reconcile(
            original, Set.of(KNOWN_DEAD, "known.Live"), Set.of("known.Live"));

    assertAll(
        "Service descriptor replacement removes only absent known providers",
        () -> assertThat(result.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.REPLACED),
        () -> assertThat(result.bytes()).containsExactly(expected));
  }

  @Test
  void omitsDescriptorsWithNoRetainedOrUnknownProviders() throws IOException {
    final byte[] deadOnly = "known.Dead\n".getBytes(StandardCharsets.UTF_8);
    final byte[] commentsOnly =
        "# no providers\r\n\n  # still no providers\n".getBytes(StandardCharsets.UTF_8);
    final byte[] blankOnly = "\r\n\n".getBytes(StandardCharsets.UTF_8);
    final byte[] deadWithComments =
        "# retain only when no declarations were removed\nknown.Dead\n"
            .getBytes(StandardCharsets.UTF_8);

    final ServiceDescriptorFilter.Result dead =
        ServiceDescriptorFilter.reconcile(deadOnly, Set.of(KNOWN_DEAD), Set.of());
    final ServiceDescriptorFilter.Result comments =
        ServiceDescriptorFilter.reconcile(commentsOnly, Set.of(), Set.of());
    final ServiceDescriptorFilter.Result blank =
        ServiceDescriptorFilter.reconcile(blankOnly, Set.of(), Set.of());
    final ServiceDescriptorFilter.Result deadAndComments =
        ServiceDescriptorFilter.reconcile(deadWithComments, Set.of(KNOWN_DEAD), Set.of());

    assertAll(
        "Service descriptor omission vs comment/blank preservation",
        () -> assertThat(dead.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.OMIT),
        () -> assertThat(deadAndComments.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.OMIT),
        () -> assertThat(comments.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.UNCHANGED),
        () -> assertThat(blank.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.UNCHANGED),
        () -> assertThat(dead.bytes()).isEmpty(),
        () -> assertThat(deadAndComments.bytes()).isEmpty(),
        () -> assertThat(comments.bytes()).containsExactly(commentsOnly),
        () -> assertThat(blank.bytes()).containsExactly(blankOnly));
  }

  @Test
  void preservesDuplicateProviderDeclarationWhenAnotherArchiveSuppliesProvider()
      throws IOException {
    final byte[] original = "known.Duplicate\nknown.Dead\n".getBytes(StandardCharsets.UTF_8);
    final byte[] expected = "known.Duplicate\n".getBytes(StandardCharsets.UTF_8);

    final ServiceDescriptorFilter.Result result =
        ServiceDescriptorFilter.reconcile(
            original, Set.of("known.Duplicate", KNOWN_DEAD), Set.of("known.Duplicate"));

    assertAll(
        "Provider supplied by another archive in the global retained set is preserved",
        () -> assertThat(result.outcome()).isEqualTo(ServiceDescriptorFilter.Outcome.REPLACED),
        () -> assertThat(result.bytes()).containsExactly(expected));
  }

  @Test
  void invalidUtf8FailsWhenDescriptorIsExamined() {
    final byte[] invalid = {(byte) 0xc3, (byte) 0x28};

    assertThatThrownBy(() -> ServiceDescriptorFilter.reconcile(invalid, Set.of(), Set.of()))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Invalid UTF-8 service descriptor");
  }
}
