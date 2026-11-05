/* WHY: Verifies persisted findings retain generic semantics without an OSV-owned nested payload. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** Tests generic cache persistence and malformed-input rejection. */
@SuppressWarnings(
    "PMD.AvoidDuplicateLiterals") // Each independent fixture keeps its values visible.
class GenericFindingCacheEnvelopeTest {
  /** Binary identity used to bind every fixture envelope. */
  private static final CacheProducerIdentity PRODUCER =
      new CacheProducerIdentity("io.github.spockz", "dependency-elider", "1.0.0", null);

  /** Creates a test instance. */
  /* package */
  GenericFindingCacheEnvelopeTest() {
    super();
  }

  @Test
  void genericSourceContributionsRoundTripWithoutNestedOsvDocument() throws IOException {
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "GHSA-only-identity",
            Set.of("GHSA-alias"),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
            FieldValue.supplied(
                Set.of(CodeClaim.declared(CodeReference.sourceFile("src/main/java/p/Foo.java")))),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "osv:GHSA-only-identity",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.REFERENCE_URL,
                    "GHSA-only-identity#reference-1",
                    java.net.URI.create("https://example.test/advisory"),
                    null)));
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            java.util.Map.of(
                FindingSource.OSV,
                new FindingSourceSnapshot(
                    FindingSource.OSV,
                    "osv-revision-1",
                    Instant.parse("2026-11-04T00:00:00Z"),
                    FindingSourceSnapshot.Status.CURRENT,
                    null,
                    List.of(contribution),
                    List.of(
                        "1 published affected entry lacked a supported Maven package identity"))));
    final GenericFindingCacheEnvelopeWriter writer = new GenericFindingCacheEnvelopeWriter();
    final GenericFindingCacheEnvelopeReader reader = new GenericFindingCacheEnvelopeReader();
    final byte[] bytes = writer.encode(envelope);
    final GenericFindingCacheEnvelope decoded =
        reader.read(new ByteArrayInputStream(bytes), PRODUCER);

    assertAll(
        () -> assertThat(decoded.contributions()).containsExactly(contribution),
        () ->
            assertThat(decoded.sources().get(FindingSource.OSV).observationDiagnostics())
                .containsExactly(
                    "1 published affected entry lacked a supported Maven package identity"),
        () ->
            assertThat(decoded.contributions())
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(value.sourceProvenance())
                            .containsExactlyElementsOf(contribution.sourceProvenance())),
        () ->
            assertThat(decoded.contributions())
                .singleElement()
                .satisfies(
                    value ->
                        assertThat(value.codeGroup().value())
                            .singleElement()
                            .satisfies(
                                claim ->
                                    assertThat(claim.reference().originalValues())
                                        .containsExactly("src/main/java/p/Foo.java"))),
        () ->
            assertThat(new String(bytes, java.nio.charset.StandardCharsets.UTF_8))
                .contains("\"sources\"")
                .doesNotContain("\"advisoryDocument\""));
  }

  @Test
  void rejectsTheSupersededNestedAdvisoryEnvelopeShape() {
    final String oldShape =
        """
        {"schemaVersion":1,"producer":{"groupId":"io.github.spockz","artifactId":"dependency-elider","version":"1.0.0","buildIdentity":"test"},"advisoryDocument":{}}
        """;

    assertThatThrownBy(
            () ->
                new GenericFindingCacheEnvelopeReader()
                    .read(
                        new ByteArrayInputStream(
                            oldShape.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                        PRODUCER))
        .isInstanceOf(IOException.class);
  }

  @Test
  void manualRowsCannotEnterThePersistedExternalFindingEnvelope() {
    final VulnerabilityFindingContribution manual =
        new VulnerabilityFindingContribution(
            "CVE-2026-12345",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1.0]")),
            FieldValue.omitted(),
            FieldValue.omitted(),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "invocation-pom",
            Set.of());

    assertThatThrownBy(
            () ->
                new FindingSourceSnapshot(
                    FindingSource.OSV,
                    "osv-revision-1",
                    Instant.parse("2026-11-04T00:00:00Z"),
                    FindingSourceSnapshot.Status.CURRENT,
                    null,
                    List.of(manual),
                    List.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsGenericContributionDocumentsWithMissingRequiredFields() throws IOException {
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-12345",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1.0]")),
            FieldValue.omitted(),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source",
            Set.of());
    final ObjectMapper mapper = new ObjectMapper();
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            java.util.Map.of(
                FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", contribution)));
    final ObjectNode root =
        (ObjectNode) mapper.readTree(new GenericFindingCacheEnvelopeWriter().encode(envelope));
    ((ObjectNode) root.path("sources").path("OSV").path("contributions").get(0))
        .remove("vulnerabilityId");

    assertThatThrownBy(
            () ->
                new GenericFindingCacheEnvelopeReader()
                    .read(new ByteArrayInputStream(mapper.writeValueAsBytes(root)), PRODUCER))
        .isInstanceOf(IOException.class);
  }

  @Test
  void replacingOneSourceSnapshotLeavesOtherSourceAssertionsIntact() {
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    final VulnerabilityFindingContribution cve = contribution("CVE-2026-12345", "cve");
    final GenericFindingCacheEnvelope original =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            java.util.Map.of(
                FindingSource.OSV,
                current(FindingSource.OSV, "osv-r1", osv),
                FindingSource.CVE_LIST,
                current(FindingSource.CVE_LIST, "cve-r1", cve)));
    final GenericFindingCacheEnvelope updated =
        original.withSourceSnapshot(
            current(FindingSource.CVE_LIST, "cve-r2", contribution("CVE-2026-12346", "cve-new")));

    assertThat(updated.contributions())
        .extracting(VulnerabilityFindingContribution::provenance)
        .containsExactlyInAnyOrder("osv", "cve-new");
  }

  @Test
  void staleSourceRetainsLastGoodAssertionsWhileSuccessfulEmptyIsExplicit() {
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    final VulnerabilityFindingContribution cve = contribution("CVE-2026-12345", "cve");
    final GenericFindingCacheEnvelope original =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            java.util.Map.of(
                FindingSource.OSV,
                current(FindingSource.OSV, "osv-r1", osv),
                FindingSource.CVE_LIST,
                current(FindingSource.CVE_LIST, "cve-r1", cve)));
    final Instant lastGoodSync = Instant.parse("2026-11-04T00:00:00Z");
    final GenericFindingCacheEnvelope cveRefreshFailed =
        original.withSourceSnapshot(
            new FindingSourceSnapshot(
                FindingSource.CVE_LIST,
                "cve-r1",
                lastGoodSync,
                FindingSourceSnapshot.Status.STALE,
                "git pull failed",
                List.of(cve),
                List.of("1 affected entry lacked Maven identity")));
    final GenericFindingCacheEnvelope cveRefreshSucceededEmpty =
        original.withSourceSnapshot(current(FindingSource.CVE_LIST, "cve-r2", null));

    assertAll(
        () ->
            assertThat(cveRefreshFailed.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .containsExactlyInAnyOrder("osv", "cve"),
        () ->
            assertThat(cveRefreshFailed.sources().get(FindingSource.CVE_LIST).status())
                .isEqualTo(FindingSourceSnapshot.Status.STALE),
        () ->
            assertThat(
                    cveRefreshFailed.sources().get(FindingSource.CVE_LIST).observationDiagnostics())
                .containsExactly("1 affected entry lacked Maven identity"),
        () ->
            assertThat(cveRefreshSucceededEmpty.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .containsExactly("osv"),
        () ->
            assertThat(
                    cveRefreshSucceededEmpty.sources().get(FindingSource.CVE_LIST).contributions())
                .isEmpty());
  }

  @Test
  void rejectsNestedTypeCoercionNullDefaultsAndInexactShapes() throws IOException {
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-12345",
            Set.of("GHSA-alias"),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.supplied(Set.of(CodeClaim.declared(CodeReference.className("p.Foo")))),
            FieldValue.supplied(
                Set.of(new PrerequisiteClaim("org.example:required", "p.Required"))),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.OSV,
                    "GHSA-alias",
                    java.net.URI.create("https://example.invalid/advisory"),
                    null)));
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode original =
        (ObjectNode)
            mapper.readTree(
                new GenericFindingCacheEnvelopeWriter()
                    .encode(
                        new GenericFindingCacheEnvelope(
                            PRODUCER,
                            java.util.Map.of(
                                FindingSource.OSV,
                                current(FindingSource.OSV, "revision", contribution)))));
    final List<CacheMutation> mutations =
        List.of(
            new CacheMutation(
                "schema integer overflow", "", node -> node.put("schemaVersion", 4_294_967_297L)),
            new CacheMutation(
                "null component type", "", node -> contributionNode(node).putNull("type")),
            new CacheMutation(
                "null classifier", "", node -> contributionNode(node).putNull("classifier")),
            new CacheMutation(
                "numeric component group", "", node -> contributionNode(node).put("groupId", 123)),
            new CacheMutation(
                "numeric identity", "", node -> contributionNode(node).put("vulnerabilityId", 123)),
            new CacheMutation(
                "ordinal priority", "", node -> contributionNode(node).put("priority", 0)),
            new CacheMutation(
                "numeric alias", "", node -> contributionNode(node).putArray("aliases").add(123)),
            new CacheMutation(
                "textual supplied boolean", "/codeGroup", node -> node.put("supplied", "true")),
            new CacheMutation(
                "null supplied boolean", "/codeGroup", node -> node.putNull("supplied")),
            new CacheMutation(
                "missing supplied boolean", "/codeGroup", node -> node.remove("supplied")),
            new CacheMutation(
                "ordinal declaration kind", "/codeGroup/value/0", node -> node.put("kind", 0)),
            new CacheMutation(
                "numeric locator", "/codeGroup/value/0/reference", node -> node.put("value", 123)),
            new CacheMutation(
                "numeric original locator",
                "/codeGroup/value/0/reference",
                node -> node.putArray("originalValues").add(123)),
            new CacheMutation(
                "numeric prerequisite class",
                "/prerequisiteGroup/value/0",
                node -> node.put("requiresClass", 123)),
            new CacheMutation(
                "ordinal version status", "/versionClaims/0", node -> node.put("status", 0)),
            new CacheMutation(
                "numeric raw predicate", "/versionClaims/0", node -> node.put("rawPredicate", 123)),
            new CacheMutation(
                "missing raw predicate", "/versionClaims/0", node -> node.remove("rawPredicate")),
            new CacheMutation(
                "ordinal provenance origin", "/sourceProvenance/0", node -> node.put("origin", 0)),
            new CacheMutation(
                "numeric provenance record ID",
                "/sourceProvenance/0",
                node -> node.put("sourceRecordId", 123)),
            new CacheMutation(
                "unknown nested field",
                "/codeGroup/value/0/reference",
                node -> node.put("unexpected", true)));

    assertAll(
        "schema-v1 nested fields retain their declared JSON types",
        mutations.stream()
            .map(
                mutation ->
                    (Executable)
                        () -> {
                          final ObjectNode changed = original.deepCopy();
                          final ObjectNode target =
                              mutation.path().isEmpty()
                                  ? changed
                                  : (ObjectNode) contributionNode(changed).at(mutation.path());
                          mutation.change().accept(target);
                          assertThatExceptionOfType(IOException.class)
                              .as(mutation.description())
                              .isThrownBy(
                                  () ->
                                      new GenericFindingCacheEnvelopeReader()
                                          .read(
                                              new ByteArrayInputStream(
                                                  mapper.writeValueAsBytes(changed)),
                                              PRODUCER));
                        }));
  }

  private static ObjectNode contributionNode(final ObjectNode root) {
    return (ObjectNode) root.at("/sources/OSV/contributions/0");
  }

  private record CacheMutation(String description, String path, Consumer<ObjectNode> change) {}

  private static FindingSourceSnapshot current(
      final FindingSource source,
      final String revision,
      final VulnerabilityFindingContribution contribution) {
    return new FindingSourceSnapshot(
        source,
        revision,
        Instant.parse("2026-11-04T00:00:00Z"),
        FindingSourceSnapshot.Status.CURRENT,
        null,
        contribution == null ? List.of() : List.of(contribution),
        List.of());
  }

  private static VulnerabilityFindingContribution contribution(
      final String vulnerabilityId, final String provenance) {
    return new VulnerabilityFindingContribution(
        vulnerabilityId,
        Set.of(),
        "org.example",
        "library",
        "jar",
        "",
        List.of(VersionCoverageClaim.affected("[1.0]")),
        FieldValue.omitted(),
        FieldValue.omitted(),
        MergePriority.AUTOMATIC,
        AssessmentIntent.AUTO_VERIFY,
        provenance,
        Set.of());
  }
}
