// WHY: Wraps text lines at a fixed column width preserving leading and hanging indentation.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies word-wrapping and subsequent indentation formatting rules. */
final class WordWrapFormatterTest {

  @Test
  void keepsLinesShorterThanMaxWidthUntouched() {
    final String line = "  - short bullet item";
    assertThat(WordWrapFormatter.wrap(line, 80)).containsExactly(line);
  }

  @Test
  void wrapsIndentedParagraphAndPreservesSubsequentIndent() {
    final String text =
        "  Exclusion provenance incomplete for 12 dependency or exclusion origins. Maven"
            + " supplied no source location/identity or the location matched zero or"
            + " multiple original POM rows. This advisory review does not affect elision.";
    final List<String> wrapped = WordWrapFormatter.wrap(text, 80);

    assertAll(
        "indented paragraph wraps to 80 chars and aligns subsequent lines with first line indent",
        () -> assertThat(wrapped.size()).isGreaterThan(1),
        () -> assertThat(wrapped).allMatch(line -> line.length() <= 80),
        () -> assertThat(wrapped).allMatch(line -> line.startsWith("  ")),
        () ->
            assertThat(wrapped.get(0))
                .isEqualTo(
                    "  Exclusion provenance incomplete for 12 dependency or exclusion"
                        + " origins. Maven"),
        () ->
            assertThat(wrapped.get(1))
                .isEqualTo(
                    "  supplied no source location/identity or the location matched zero"
                        + " or multiple"),
        () ->
            assertThat(wrapped.get(2))
                .isEqualTo("  original POM rows. This advisory review does not affect elision."));
  }

  @Test
  void wrapsBulletListItemWithSubsequentHangingIndent() {
    final String text =
        "  - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18; inactive because missing"
            + " prerequisite dependencies: ch.qos.logback:logback-access";
    final List<String> wrapped = WordWrapFormatter.wrap(text, 80);

    assertAll(
        "bullet item wraps to 80 chars with hanging indent matching the first item text position",
        () -> assertThat(wrapped.size()).isEqualTo(2),
        () -> assertThat(wrapped.get(0)).startsWith("  - "),
        () -> assertThat(wrapped.get(1)).startsWith("    "),
        () -> assertThat(wrapped).allMatch(line -> line.length() <= 80),
        () ->
            assertThat(wrapped.get(0))
                .isEqualTo(
                    "  - CVE-2025-11226 ch.qos.logback:logback-core:jar:1.5.18; inactive"
                        + " because"),
        () ->
            assertThat(wrapped.get(1))
                .isEqualTo("    missing prerequisite dependencies: ch.qos.logback:logback-access"));
  }

  @Test
  void wrapsFourSpaceIndentedLinesPreservingIndent() {
    final String text =
        "    Heuristic candidates are review leads; they do not establish a complete affected"
            + " class set.";
    final List<String> wrapped = WordWrapFormatter.wrap(text, 80);

    assertAll(
        "four-space indented text wraps with four spaces on subsequent lines",
        () -> assertThat(wrapped.size()).isEqualTo(2),
        () -> assertThat(wrapped).allMatch(line -> line.startsWith("    ")),
        () -> assertThat(wrapped).allMatch(line -> line.length() <= 80),
        () ->
            assertThat(wrapped.get(0))
                .isEqualTo(
                    "    Heuristic candidates are review leads; they do not establish a"
                        + " complete"),
        () -> assertThat(wrapped.get(1)).isEqualTo("    affected class set."));
  }

  @Test
  void doesNotSplitAtomicUrlsEvenIfExceedingMaxWidth() {
    final String text =
        "    Source URL: https://example.test/very/long/path/to/advisory/reference/with/many/parameters/and/commit/hash/1234567890abcdef1234567890abcdef1234567890abcdef";
    final List<String> wrapped = WordWrapFormatter.wrap(text, 80);

    assertAll(
        "atomic URLs are preserved without being split across lines",
        () -> assertThat(wrapped.size()).isEqualTo(2),
        () -> assertThat(wrapped.get(0)).isEqualTo("    Source URL:"),
        () ->
            assertThat(wrapped.get(1))
                .isEqualTo(
                    "    https://example.test/very/long/path/to/advisory/reference/with/many/parameters/and/commit/hash/1234567890abcdef1234567890abcdef1234567890abcdef"));
  }
}
