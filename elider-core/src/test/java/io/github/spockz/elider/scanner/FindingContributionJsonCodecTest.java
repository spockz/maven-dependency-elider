/* WHY: Shares one strict contribution format between cache and saved project reports. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Checks generic project data can reuse the strict external contribution shape. */
@SuppressWarnings("PMD.LawOfDemeter")
class FindingContributionJsonCodecTest {
  /** Creates a test instance. */
  /* package */
  FindingContributionJsonCodecTest() {
    super();
  }

  @Test
  void manualReportRowsPreserveOmissionEmptyGroupsAndOriginalLocatorSpellings() throws IOException {
    final VulnerabilityFindingContribution mapped =
        new VulnerabilityFindingContribution(
            "CVE-2026-10000",
            Set.of("GHSA-alias"),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.sourceFile("src/main/java/p/Foo.java")))),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "project-row",
            Set.of());
    final VulnerabilityFindingContribution empty =
        new VulnerabilityFindingContribution(
            "CVE-2026-10001",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.supplied(Set.of()),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "empty-project-row",
            Set.of());
    final JsonNode encoded = FindingContributionJsonCodec.encode(List.of(mapped, empty));
    final List<VulnerabilityFindingContribution> decoded =
        FindingContributionJsonCodec.decode(encoded);

    assertAll(
        () -> assertThat(decoded).containsExactly(mapped, empty),
        () ->
            assertThat(decoded.getFirst().codeGroup().value())
                .singleElement()
                .satisfies(
                    claim ->
                        assertThat(claim.reference().originalValues())
                            .containsExactly("src/main/java/p/Foo.java")),
        () -> assertThat(encoded.at("/1/codeGroup/supplied").booleanValue()).isTrue(),
        () -> assertThat(encoded.at("/1/codeGroup/value").isArray()).isTrue(),
        () -> assertThat(encoded.at("/1/codeGroup/value")).isEmpty(),
        () -> assertThat(decoded.getFirst().prerequisiteGroup()).isEqualTo(FieldValue.omitted()));
  }
}
