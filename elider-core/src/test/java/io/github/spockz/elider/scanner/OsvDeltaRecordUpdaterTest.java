/* WHY: Verifies delta replacement is isolated to one OSV owner and staged atomically. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Verifies owner-specific delta replacement and refusal behavior. */
/* Package visibility keeps updater tests package-scoped. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
class OsvDeltaRecordUpdaterTest {
  /** Owner used for first-record replacement assertions. */
  private static final String OWNER_ONE = "GHSA-owner-one";

  /** Owner sharing an alias with other OSV records. */
  private static final String OWNER_TWO = "GHSA-owner-two";

  /** Owner whose replacement leaves the Maven ecosystem. */
  private static final String OWNER_LEAVES_MAVEN = "GHSA-leaves-maven";

  /** New owner introduced by a modified-ID row. */
  private static final String OWNER_NEW = "GHSA-new-owner";

  /** Owner removed by an explicit withdrawn source record. */
  private static final String OWNER_WITHDRAWN = "GHSA-withdrawn";

  /** Unchanged owner retained through another owner's withdrawal. */
  private static final String OWNER_SURVIVOR = "GHSA-survivor";

  /** Timestamp shared by original source fixtures. */
  private static final String BASE_MODIFIED = "2026-10-30T10:00:00Z";

  /** Baseline chosen so the maximum duplicate revision must trigger a fetch. */
  private static final String OWNER_ONE_BASELINE = "2026-10-31T10:50:00Z";

  /** Maven ecosystem claim used by package fixtures. */
  private static final String MAVEN_ECOSYSTEM = "Maven";

  /** Missing checkout path keeps these tests isolated from local CVEList data. */
  private static final String MISSING_CVE_LIST = "missing-cvelist";

  /** Maven identity used in the owner replacement fixtures. */
  private static final String LIBRARY_PACKAGE = "org.example:library";

  /** Shared alias proves updates preserve distinct OSV owners. */
  private static final String SHARED_CVE = "CVE-2026-12345";

  /** Revision chosen for changed-owner fixtures. */
  private static final String NEW_REVISION = "2026-10-31T11:00:00Z";

  /** Older revision used by stale response checks. */
  private static final String STALE_REVISION = "2026-10-31T10:59:00Z";

  /** Owner shared by malformed and response identity refusal scenarios. */
  private static final String SIMPLE_OWNER = "GHSA-owner";

  /** Stateful fixture owns a reusable stateless updater. */
  private final OsvDeltaRecordUpdater updater;

  /** Initializes the reusable test updater. */
  // The default access modifier lets JUnit construct the test fixture.
  OsvDeltaRecordUpdaterTest() {
    updater = new OsvDeltaRecordUpdater();
  }

  @Test
  void replacesOnlyChangedOwnersAndRetainsDuplicateCveOwners() throws IOException {
    final List<OsvAdvisoryRecord> baseline =
        List.of(
            indexed(OWNER_ONE, OWNER_ONE_BASELINE, MAVEN_ECOSYSTEM, "org.example:old"),
            indexed(OWNER_TWO, "2026-10-31T12:00:00Z", MAVEN_ECOSYSTEM, "org.example:stable"),
            indexed(OWNER_LEAVES_MAVEN, BASE_MODIFIED, MAVEN_ECOSYSTEM, "org.example:old"));
    final AtomicInteger fetches = new AtomicInteger();
    final List<OsvAdvisoryRecord> updated =
        updater.apply(
            stream(
                NEW_REVISION
                    + ",GHSA-owner-one\n"
                    + "2026-10-31T10:45:00Z,GHSA-owner-one\n"
                    + NEW_REVISION
                    + ",GHSA-owner-two\n"
                    + "2026-10-31T13:00:00Z,GHSA-leaves-maven\n"
                    + "2026-10-31T14:00:00Z,GHSA-new-owner\n"),
            baseline,
            Path.of(MISSING_CVE_LIST),
            id -> {
              fetches.incrementAndGet();
              return switch (id) {
                case OWNER_ONE ->
                    sourceRecord(id, NEW_REVISION, MAVEN_ECOSYSTEM, "org.example:updated", null);
                case OWNER_LEAVES_MAVEN ->
                    sourceRecord(id, "2026-10-31T13:00:00Z", "npm", "example-package", null);
                case OWNER_NEW ->
                    sourceRecord(
                        id, "2026-10-31T14:00:00Z", MAVEN_ECOSYSTEM, "org.example:new", null);
                default -> throw new IOException("Unexpected fetch for " + id);
              };
            });
    assertAll(
        () -> assertThat(fetches).hasValue(3),
        () ->
            assertThat(updated)
                .extracting(OsvAdvisoryRecord::osvId)
                .containsExactly(OWNER_LEAVES_MAVEN, OWNER_NEW, OWNER_ONE, OWNER_TWO),
        () ->
            assertThat(record(updated, OWNER_ONE).affectedPackages())
                .singleElement()
                .satisfies(
                    affected ->
                        assertThat(affected.packageName()).isEqualTo("org.example:updated")),
        () -> assertThat(record(updated, OWNER_TWO).aliases()).containsExactly(SHARED_CVE),
        () -> assertThat(record(updated, OWNER_LEAVES_MAVEN).affectedPackages()).isEmpty(),
        () -> assertThat(record(updated, OWNER_NEW).aliases()).contains(SHARED_CVE));
  }

  @Test
  void withdrawalRemovesOnlyItsOsvRecordOwner() throws IOException {
    final List<OsvAdvisoryRecord> baseline =
        List.of(
            indexed(OWNER_WITHDRAWN, BASE_MODIFIED, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE),
            indexed(OWNER_SURVIVOR, BASE_MODIFIED, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE));
    final List<OsvAdvisoryRecord> updated =
        updater.apply(
            stream(NEW_REVISION + ",GHSA-withdrawn\n"),
            baseline,
            Path.of(MISSING_CVE_LIST),
            id ->
                sourceRecord(
                    id, NEW_REVISION, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE, "2026-10-31T10:00:00Z"));
    assertAll(
        () ->
            assertThat(updated)
                .extracting(OsvAdvisoryRecord::osvId)
                .containsExactly(OWNER_SURVIVOR),
        () -> assertThat(record(updated, OWNER_SURVIVOR).aliases()).containsExactly(SHARED_CVE));
  }

  @Test
  void malformedCsvAndFetchFailuresDoNotMutateInputSnapshot() throws IOException {
    final List<OsvAdvisoryRecord> baseline =
        List.of(indexed(SIMPLE_OWNER, BASE_MODIFIED, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE));
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        updater.apply(
                            stream("invalid," + SIMPLE_OWNER + "\n"),
                            baseline,
                            Path.of(MISSING_CVE_LIST),
                            ignored ->
                                sourceRecord(
                                    SIMPLE_OWNER,
                                    NEW_REVISION,
                                    MAVEN_ECOSYSTEM,
                                    LIBRARY_PACKAGE,
                                    null)))
                .isInstanceOf(IOException.class),
        () ->
            assertThatThrownBy(
                    () ->
                        updater.apply(
                            stream(NEW_REVISION + "," + SIMPLE_OWNER + "\n"),
                            baseline,
                            Path.of(MISSING_CVE_LIST),
                            ignored -> {
                              throw new IOException("fixture HTTP 404");
                            }))
                .isInstanceOf(IOException.class),
        () ->
            assertThat(baseline)
                .singleElement()
                .satisfies(value -> assertThat(value.modified()).isEqualTo(BASE_MODIFIED)));
  }

  @Test
  void fetchedWrongRecordIdIsRejectedWithoutChangingInputSnapshot() throws IOException {
    final List<OsvAdvisoryRecord> baseline =
        List.of(indexed(SIMPLE_OWNER, BASE_MODIFIED, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE));
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        updater.apply(
                            stream(NEW_REVISION + "," + SIMPLE_OWNER + "\n"),
                            baseline,
                            Path.of(MISSING_CVE_LIST),
                            ignored ->
                                sourceRecord(
                                    "GHSA-other",
                                    NEW_REVISION,
                                    MAVEN_ECOSYSTEM,
                                    LIBRARY_PACKAGE,
                                    null)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("ID does not match"),
        () ->
            assertThat(baseline)
                .singleElement()
                .satisfies(value -> assertThat(value.osvId()).isEqualTo(SIMPLE_OWNER)));
  }

  @Test
  void staleActiveAndWithdrawalResponsesAreRejectedWithoutChangingInputSnapshot()
      throws IOException {
    assertAll(
        "active and withdrawn responses must meet the selected revision",
        () -> assertStaleResponseIsRejected(null),
        () -> assertStaleResponseIsRejected(STALE_REVISION));
  }

  private void assertStaleResponseIsRejected(final String withdrawn) throws IOException {
    final List<OsvAdvisoryRecord> baseline =
        List.of(indexed(SIMPLE_OWNER, BASE_MODIFIED, MAVEN_ECOSYSTEM, LIBRARY_PACKAGE));
    assertAll(
        () ->
            assertThatThrownBy(
                    () ->
                        updater.apply(
                            stream(NEW_REVISION + "," + SIMPLE_OWNER + "\n"),
                            baseline,
                            Path.of(MISSING_CVE_LIST),
                            ignored ->
                                sourceRecord(
                                    SIMPLE_OWNER,
                                    STALE_REVISION,
                                    MAVEN_ECOSYSTEM,
                                    LIBRARY_PACKAGE,
                                    withdrawn)))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("older than selected revision"),
        () ->
            assertThat(baseline)
                .singleElement()
                .satisfies(value -> assertThat(value.modified()).isEqualTo(BASE_MODIFIED)));
  }

  private static OsvAdvisoryRecord indexed(
      final String recordId,
      final String modified,
      final String ecosystem,
      final String packageName)
      throws IOException {
    return new OsvSnapshotIndexer()
        .indexRecord(
            sourceRecord(recordId, modified, ecosystem, packageName, null),
            Path.of(MISSING_CVE_LIST),
            recordId)
        .advisory()
        .orElseThrow();
  }

  private static byte[] sourceRecord(
      final String recordId,
      final String modified,
      final String ecosystem,
      final String packageName,
      final String withdrawn)
      throws IOException {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode root = mapper.createObjectNode();
    root.put("id", recordId);
    root.put("modified", modified);
    root.putArray("aliases").add(SHARED_CVE);
    if (withdrawn != null) {
      root.put("withdrawn", withdrawn);
    }
    final ObjectNode affected = root.putArray("affected").addObject();
    affected.putObject("package").put("ecosystem", ecosystem).put("name", packageName);
    affected.putArray("versions").add("1.0");
    return mapper.writeValueAsBytes(root);
  }

  private static OsvAdvisoryRecord record(
      final List<OsvAdvisoryRecord> records, final String recordId) {
    return records.stream()
        .filter(value -> value.osvId().equals(recordId))
        .findFirst()
        .orElseThrow();
  }

  private static ByteArrayInputStream stream(final String rows) {
    return new ByteArrayInputStream(rows.getBytes(StandardCharsets.UTF_8));
  }
}
