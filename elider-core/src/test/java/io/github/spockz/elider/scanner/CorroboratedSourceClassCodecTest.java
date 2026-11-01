/* WHY: Verifies artifact-bound corroboration context survives the strict v1 codec. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AdvisoryScope;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.CorroboratedSourceClassCandidate;
import io.github.spockz.elider.model.CveAffectedEntryContext;
import io.github.spockz.elider.model.CveVersionClaim;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.OsvAdvisoryRecord;
import io.github.spockz.elider.model.OsvAffectedPackage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Checks review-candidate archive context in the strict codec. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
class CorroboratedSourceClassCodecTest {
  /** CVE used to bind the test candidate to its OSV owner. */
  private static final String CVE_ID = "CVE-2025-12345";

  /** Exact CNA affected-entry locator serialized with the candidate. */
  private static final String ENTRY_ID = "containers.cna.affected[0]";

  /** Java source claim retained by the linked CNA entry. */
  private static final String PROGRAM_FILE = "src/main/java/org/example/Example.java";

  @Test
  void roundTripsCorroboratedArtifactContext() throws IOException {
    final OsvAdvisoryRecord record = record();
    final List<OsvAdvisoryRecord> decoded =
        new AdvisoryEvidenceReader()
            .read(new ByteArrayInputStream(new AdvisoryEvidenceWriter().encode(List.of(record))));

    assertThat(decoded).containsExactly(record);
  }

  @Test
  void modelRejectsCorroborationWhenCnaClaimsMixExactVersionsWithRangesOrConflicts() {
    assertAll(
        "persisted candidates cannot upgrade ranged or conflicting CNA claims",
        () ->
            assertThatThrownBy(
                    () ->
                        recordWithClaims(
                            List.of(
                                exactAffectedClaim(),
                                new CveVersionClaim(
                                    "0.9", "affected", null, "1.1", null, List.of()))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exact CNA product/version claim"),
        () ->
            assertThatThrownBy(
                    () ->
                        recordWithClaims(
                            List.of(
                                exactAffectedClaim(),
                                new CveVersionClaim(
                                    "1.0", "unaffected", null, null, null, List.of()))))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exact CNA product/version claim"));
  }

  private static OsvAdvisoryRecord record() {
    return recordWithClaims(List.of(exactAffectedClaim()));
  }

  private static OsvAdvisoryRecord recordWithClaims(final List<CveVersionClaim> versions) {
    final AdvisoryScope scope =
        new AdvisoryScope(
            CVE_ID,
            ArtifactCoordinate.of("org.example", "library", null),
            "[1.0,2.0)",
            "Maven",
            "org.example:library");
    final ArtifactCoordinate artifact = ArtifactCoordinate.of("org.example", "library", "1.0");
    final CveAffectedEntryContext entry =
        new CveAffectedEntryContext(
            ENTRY_ID,
            "Example",
            "library",
            "pkg:maven/org.example/library",
            null,
            "affected",
            versions,
            Set.of(PROGRAM_FILE),
            Set.of());
    final CorroboratedSourceClassCandidate candidate =
        new CorroboratedSourceClassCandidate(
            scope,
            new AdvisoryProvenance(EvidenceOrigin.CVE_LIST, CVE_ID, null, "a".repeat(64)),
            ENTRY_ID,
            artifact,
            "b".repeat(64),
            "META-INF/versions/17/org/example/Example.class",
            17,
            "Example:library",
            PROGRAM_FILE,
            "org.example.Example",
            "Example.java",
            "package suffix matches; complete source output set is unresolved",
            false,
            CorroboratedSourceClassCandidate.MappingStatus.INCOMPLETE_REVIEW_ONLY);
    return new OsvAdvisoryRecord(
        "GHSA-corroborated",
        "2026-10-31T00:00:00Z",
        Set.of(CVE_ID),
        List.of(
            new OsvAffectedPackage(
                "Maven", "org.example:library", scope.affectedCoordinate(), List.of(), List.of())),
        List.of(entry),
        List.of(candidate));
  }

  private static CveVersionClaim exactAffectedClaim() {
    return new CveVersionClaim("1.0", "affected", "semver", null, null, List.of());
  }
}
