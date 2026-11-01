/* WHY: Proves OSV modification rows are parsed strictly before delta fetching. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Verifies strict timestamp, record-ID and row-shape parsing. */
/* Package visibility keeps the reader fixture limited to the scanner test package. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
class OsvModifiedIdReaderTest {
  /** Reader reused across isolated test invocations. */
  private final OsvModifiedIdReader reader;

  /** Initializes the reusable reader test fixture. */
  // The default access modifier lets JUnit construct the test fixture.
  OsvModifiedIdReaderTest() {
    reader = new OsvModifiedIdReader();
  }

  @Test
  void readsPerEcosystemTimestampAndRecordIdRows() throws IOException {
    final List<OsvModifiedIdReader.ModifiedId> rows = new ArrayList<>();
    reader.read(
        stream("2026-10-31T12:00:00Z,GHSA-updated\n2026-10-30T12:00:00Z,CVE-2026-12345\n"),
        rows::add);
    assertAll(
        () -> assertThat(rows).hasSize(2),
        () -> assertThat(rows.getFirst().recordId()).isEqualTo("GHSA-updated"),
        () ->
            assertThat(rows.getFirst().modified()).isEqualTo(Instant.parse("2026-10-31T12:00:00Z")),
        () -> assertThat(rows.get(1).recordId()).isEqualTo("CVE-2026-12345"));
  }

  @Test
  void rejectsMalformedRowsAndTimestamps() {
    assertAll(
        () -> assertRejected("not-a-timestamp,GHSA-record"),
        () -> assertRejected("2026-10-31T12:00:00Z,"),
        () -> assertRejected("2026-10-31T12:00:00Z,GHSA/record"),
        () -> assertRejected("2026-10-31T12:00:00Z,GHSA-one,extra"));
  }

  private void assertRejected(final String row) {
    assertThatThrownBy(() -> reader.read(stream(row), ignored -> {}))
        .isInstanceOf(IOException.class);
  }

  private static ByteArrayInputStream stream(final String value) {
    return new ByteArrayInputStream(value.getBytes(StandardCharsets.UTF_8));
  }
}
