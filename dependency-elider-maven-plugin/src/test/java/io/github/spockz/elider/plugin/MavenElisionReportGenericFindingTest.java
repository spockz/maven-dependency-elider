/* WHY: Ensures saved generic findings replay captured decisions without live source inputs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.spockz.elider.engine.ClassUsageReport;
import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.metadata.OpenVexGenerator;
import io.github.spockz.elider.model.AdvisoryProvenance;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.ClaimGroupStatus;
import io.github.spockz.elider.model.CodeAttributionResolver;
import io.github.spockz.elider.model.CodeClaim;
import io.github.spockz.elider.model.CodeReference;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.OmittedCodeProof;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VexAttestation;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import io.github.spockz.elider.scanner.FindingSource;
import io.github.spockz.elider.scanner.FindingSourceSnapshot;
import io.github.spockz.elider.scanner.GenericFindingCacheEnvelope;
import io.github.spockz.elider.scanner.GenericFindingCacheEnvelopeWriter;
import io.github.spockz.elider.scanner.VulnerabilityCacheManager;
import io.github.spockz.elider.trimmer.ArtifactDigests;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises persisted generic reports and real proof output. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidDuplicateLiterals"
})
class MavenElisionReportGenericFindingTest {
  /** Isolated report and archive directory. */
  @TempDir private Path temp;

  /** Creates the fixture. */
  /* package */ MavenElisionReportGenericFindingTest() {
    super();
  }

  @Test
  void savesAndReplaysCapturedFindingsAndIndependentSourceHealth() throws IOException {
    final GenericFindingAssessment finding = finding();
    final List<FindingSourceObservation> sources =
        List.of(
            new FindingSourceObservation(
                Optional.of(FindingSource.OSV),
                FindingSourceObservation.Status.CURRENT,
                "revision",
                Instant.parse("2026-11-04T12:00:00Z"),
                null,
                List.of("record warning"),
                1),
            new FindingSourceObservation(
                Optional.of(FindingSource.CVE_LIST),
                FindingSourceObservation.Status.STALE,
                "old-revision",
                Instant.parse("2026-11-03T12:00:00Z"),
                "refresh failed",
                List.of("retained snapshot"),
                2),
            new FindingSourceObservation(
                Optional.empty(),
                FindingSourceObservation.Status.UNAVAILABLE,
                null,
                null,
                "cache unavailable",
                List.of(),
                0));
    final MavenElisionReportSnapshot original = snapshot(finding, sources);
    final Path output = temp.resolve("report.json");
    MavenElisionReportWriter.write(output, original);
    final String json = Files.readString(output);
    final MavenElisionReportSnapshot loaded = MavenElisionReportWriter.read(output);
    final String rendered = String.join("\n", MavenElisionReportWriter.render(loaded));
    assertAll(
        () ->
            assertThat(loaded.genericFindings())
                .usingRecursiveComparison()
                .ignoringCollectionOrder()
                .isEqualTo(original.genericFindings()),
        () -> assertThat(loaded.sourceObservations()).containsExactlyInAnyOrderElementsOf(sources),
        () ->
            assertThat(json)
                .contains(
                    "\"genericFindings\"",
                    "\"sourceObservations\"",
                    "GHSA-only",
                    "[1,2)",
                    "[3,4)",
                    "src/main/java/p/Example.java",
                    "cache unavailable",
                    "refresh failed",
                    "https://example.test/advisory",
                    "a".repeat(64)),
        () ->
            assertThat(json)
                .doesNotContain(
                    "\"advisoryReview\"",
                    "\"sourceReviewFindings\"",
                    "\"verifiedStructuredProofs\""),
        () ->
            assertThat(rendered)
                .contains(
                    "GHSA-only",
                    "UNRESOLVED",
                    "CLASS_NOT_FOUND",
                    "org.example:first",
                    "org.example:second",
                    "cache unavailable",
                    "refresh failed",
                    "OVERRIDE",
                    "ENRICHED",
                    "https://example.test/advisory",
                    "a".repeat(64)));
  }

  @Test
  void failedSourceRefreshAndCachePublicationSurviveAssessmentReportReplay() throws IOException {
    final Path cache = temp.resolve("failed-publication-cache");
    Files.createDirectories(cache);
    final GenericFindingAssessment fixture = finding();
    final VulnerabilityFindingContribution cachedContribution =
        new VulnerabilityFindingContribution(
            "GHSA-cache-only",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.omitted(),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "osv:GHSA-cache-only",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.REFERENCE_URL, "GHSA-cache-only", null, null)));
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            MavenAssessmentFixtures.CACHE_PRODUCER,
            Map.of(
                FindingSource.OSV,
                new FindingSourceSnapshot(
                    FindingSource.OSV,
                    "last-good-revision",
                    Instant.parse("2026-11-04T12:00:00Z"),
                    FindingSourceSnapshot.Status.CURRENT,
                    null,
                    List.of(cachedContribution),
                    List.of())));
    Files.write(
        cache.resolve("index.json"), new GenericFindingCacheEnvelopeWriter().encode(envelope));
    Files.createDirectories(cache.resolve("index.json.tmp"));
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            cache,
            URI.create("http://127.0.0.1:1/osv/all.zip"),
            null,
            Duration.ZERO,
            true,
            false,
            VulnerabilityCacheManager.bundledEmptySeed(),
            Optional.of(MavenAssessmentFixtures.CACHE_PRODUCER),
            Optional.empty());

    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(
                config, ConfiguredVulnerabilityMappings.empty(), List.of(), List.of(), List.of());
    final MavenElisionReportSnapshot sourceSnapshot =
        snapshot(fixture, result.sourceObservations());
    final Path report = temp.resolve("failed-publication-report.json");
    MavenElisionReportWriter.write(report, sourceSnapshot);
    final MavenElisionReportSnapshot replayed = MavenElisionReportWriter.read(report);

    assertAll(
        "the report preserves the latest cache-level failure beside last-good source data",
        () ->
            assertThat(result.sourceObservations())
                .anySatisfy(
                    observation ->
                        assertAll(
                            () -> assertThat(observation.source()).isEmpty(),
                            () ->
                                assertThat(observation.status())
                                    .isEqualTo(FindingSourceObservation.Status.ERROR),
                            () ->
                                assertThat(observation.diagnostic())
                                    .contains("last-good source snapshots remain available")
                                    .contains("OSV source is stale", "publication failed"))),
        () ->
            assertThat(replayed.sourceObservations())
                .usingRecursiveFieldByFieldElementComparator()
                .containsExactlyInAnyOrderElementsOf(result.sourceObservations()),
        () ->
            assertThat(replayed.sourceObservations())
                .anySatisfy(
                    observation ->
                        assertThat(observation.status())
                            .isEqualTo(FindingSourceObservation.Status.CURRENT)));
  }

  @Test
  void realGenericProofPreservesSourceDetailsThroughVexAndOfflineReport() throws Exception {
    final Path original = jar("original.jar", true);
    final Path trimmed = jar("trimmed.jar", false);
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "library", "1.5");
    final ArtifactDigests before = ArtifactDigests.read(original);
    final ArtifactDigests after = ArtifactDigests.read(trimmed);
    final ArtifactTrimRecord record =
        new ArtifactTrimRecord(
            coordinate,
            original,
            before.sha256(),
            before.sha1(),
            trimmed,
            after.sha256(),
            after.sha1(),
            1,
            0,
            1);
    final CodeClaim code = CodeClaim.declared(CodeReference.className("p.Example"));
    final CodeClaim heuristic = CodeClaim.heuristic(CodeReference.className("p.Other"));
    final AdvisoryProvenance source =
        new AdvisoryProvenance(
            EvidenceOrigin.CVE_LIST,
            "CVE-2026-12345",
            URI.create("https://example.test/source"),
            "c".repeat(64));
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-12345",
            Set.of(),
            coordinate.groupId(),
            coordinate.artifactId(),
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)")),
            FieldValue.supplied(Set.of(code, heuristic)),
            FieldValue.omitted(),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "source-label",
            Set.of(source));
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(contribution));
    final VexAttestation proof = OmittedCodeProof.prove(finding, record, false);
    final GenericFindingAssessment row =
        new GenericFindingAssessment(
            "CVE-2026-12345",
            Set.of(),
            coordinate,
            VersionApplicability.AFFECTED,
            Optional.of(AssessmentIntent.AUTO_VERIFY),
            ClaimGroupStatus.DECLARED,
            List.of(
                new CodeAttributionResolver.DeclarationResult(
                    code, CodeAttributionResolver.Status.RESOLVED, Set.of("p.Example"), List.of()),
                new CodeAttributionResolver.DeclarationResult(
                    heuristic,
                    CodeAttributionResolver.Status.REVIEW_LEAD,
                    Set.of(),
                    List.of(CodeAttributionResolver.Reason.HEURISTIC_REQUIRES_REVIEW))),
            List.of(heuristic.reference()),
            ClaimGroupStatus.UNRESOLVED,
            List.of(),
            List.of(VersionCoverageClaim.unresolvedRange("[1,2)", "unknown prerequisite scope")),
            Set.of(),
            Set.of(),
            GenericFindingAssessment.Outcome.DECLARED_CODE_ABSENT,
            "verified absence",
            MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
            List.of(contribution));
    final Path report = temp.resolve("proof-report.json");
    MavenElisionReportWriter.write(report, snapshot(row, List.of()));
    final ArtifactFileRef inventory = ArtifactFileRef.fromPath(coordinate, trimmed);
    final CycloneDxSbomGenerator.RootIdentity root =
        new CycloneDxSbomGenerator.RootIdentity("org.example", "consumer", "1", "Consumer");
    final Instant timestamp = Instant.parse("2026-11-04T12:00:00Z");
    assertAll(
        () -> {
          final Path bom = temp.resolve("bom.json");
          new CycloneDxSbomGenerator()
              .write(
                  bom,
                  root,
                  List.of(inventory),
                  new ElisionDecision(Set.of(coordinate), Set.of(), Map.of(), Map.of(), 0),
                  new CycloneDxSbomGenerator.DocumentMetadata(
                      "urn:uuid:123e4567-e89b-12d3-a456-426614174000", 1, timestamp, "elider", "1"),
                  List.of(record),
                  List.of(proof));
          final String cdx = Files.readString(bom);
          assertAll(
              () ->
                  assertThat(cdx)
                      .contains(
                          "CVE-2026-12345",
                          after.sha256(),
                          "source-label",
                          "https://example.test/source"),
              () ->
                  assertSchema(
                      cdx, "bom-1.6.schema.json", com.networknt.schema.SpecVersion.VersionFlag.V7));
        },
        () -> {
          final String vex =
              new String(
                  new OpenVexGenerator()
                      .generate(
                          root,
                          List.of(inventory),
                          List.of(proof),
                          new OpenVexGenerator.DocumentMetadata(
                              "https://example.test/vex", "author", "tool", timestamp, 1)),
                  java.nio.charset.StandardCharsets.UTF_8);
          assertAll(
              () ->
                  assertThat(vex)
                      .contains(
                          "CVE-2026-12345",
                          after.sha256(),
                          "source-label",
                          "https://example.test/source"),
              () ->
                  assertSchema(
                      vex,
                      "openvex-0.2.0.schema.json",
                      com.networknt.schema.SpecVersion.VersionFlag.V202012));
        },
        () -> {
          Files.delete(original);
          Files.delete(trimmed);
          final String replay =
              String.join(
                  "\n", MavenElisionReportWriter.render(MavenElisionReportWriter.read(report)));
          assertThat(replay)
              .contains(
                  "CVE-2026-12345",
                  "DECLARED_CODE_ABSENT",
                  "p.Example",
                  "source-label",
                  "https://example.test/source");
        });
  }

  private static void assertSchema(
      final String document,
      final String filename,
      final com.networknt.schema.SpecVersion.VersionFlag version)
      throws IOException {
    final ObjectMapper mapper = new ObjectMapper();
    final Path schema = Path.of("../elider-core/src/test/resources/schema", filename);
    assertThat(
            com.networknt.schema.JsonSchemaFactory.getInstance(version)
                .getSchema(mapper.readTree(Files.readAllBytes(schema)))
                .validate(mapper.readTree(document)))
        .isEmpty();
  }

  private Path jar(final String name, final boolean withClass) throws IOException {
    final Path path = temp.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      if (withClass) {
        final ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "p/Example", null, "java/lang/Object", null);
        writer.visitEnd();
        output.putNextEntry(new JarEntry("p/Example.class"));
        output.write(writer.toByteArray());
        output.closeEntry();
      }
    }
    return path;
  }

  @Test
  void changingSourceLabelsChangesDisplayButNotSavedDecision() throws IOException {
    final GenericFindingAssessment original = finding();
    final GenericFindingAssessment relabeled =
        new GenericFindingAssessment(
            original.vulnerabilityId(),
            original.aliases(),
            original.candidate(),
            original.applicability(),
            original.intent(),
            original.codeGroupStatus(),
            original.codeAttribution(),
            original.heuristicLeads(),
            original.prerequisiteGroupStatus(),
            original.effectivePrerequisites(),
            original.unresolvedVersionClaims(),
            original.overriddenFields(),
            original.enrichedFields(),
            original.outcome(),
            original.detail(),
            original.inventoryDisposition(),
            List.of(original.contributions().getFirst().withProvenance("other label")));
    final MavenElisionReportSnapshot base = snapshot(original, List.of());
    final Path first = temp.resolve("first-source.json");
    final Path second = temp.resolve("second-source.json");
    MavenElisionReportWriter.write(first, base.withGenericFindings(List.of(original), List.of()));
    MavenElisionReportWriter.write(second, base.withGenericFindings(List.of(relabeled), List.of()));
    final MavenElisionReportSnapshot firstSaved = MavenElisionReportWriter.read(first);
    final MavenElisionReportSnapshot secondSaved = MavenElisionReportWriter.read(second);
    assertAll(
        () -> assertThat(firstSaved.genericFindings()).hasSize(1),
        () -> assertThat(secondSaved.genericFindings()).hasSize(1),
        () ->
            assertThat(firstSaved.genericFindings().getFirst().outcome())
                .isEqualTo(secondSaved.genericFindings().getFirst().outcome()),
        () ->
            assertThat(firstSaved.genericFindings().getFirst().codeAttribution())
                .isEqualTo(secondSaved.genericFindings().getFirst().codeAttribution()),
        () ->
            assertThat(MavenElisionReportWriter.render(firstSaved).toString())
                .contains("manual source")
                .doesNotContain("other label"),
        () ->
            assertThat(MavenElisionReportWriter.render(secondSaved).toString())
                .contains("other label")
                .doesNotContain("manual source"));
  }

  @Test
  void genericRowsAndSourceHealthHaveStableOrder() throws IOException {
    final GenericFindingAssessment first = finding();
    final GenericFindingAssessment second =
        new GenericFindingAssessment(
            first.vulnerabilityId(),
            first.aliases(),
            ArtifactCoordinate.of("org.example", "library", "3.5"),
            first.applicability(),
            first.intent(),
            first.codeGroupStatus(),
            first.codeAttribution(),
            first.heuristicLeads(),
            first.prerequisiteGroupStatus(),
            first.effectivePrerequisites(),
            first.unresolvedVersionClaims(),
            first.overriddenFields(),
            first.enrichedFields(),
            first.outcome(),
            first.detail(),
            first.inventoryDisposition(),
            first.contributions());
    final FindingSourceObservation current =
        new FindingSourceObservation(
            Optional.of(FindingSource.OSV),
            FindingSourceObservation.Status.CURRENT,
            "rev",
            Instant.parse("2026-11-04T12:00:00Z"),
            null,
            List.of(),
            1);
    final FindingSourceObservation unavailable =
        new FindingSourceObservation(
            Optional.empty(),
            FindingSourceObservation.Status.UNAVAILABLE,
            null,
            null,
            "cache unavailable",
            List.of(),
            0);
    final MavenElisionReportSnapshot base = snapshot(first, List.of());
    final Path forward = temp.resolve("forward.json");
    final Path reverse = temp.resolve("reverse.json");
    MavenElisionReportWriter.write(
        forward, base.withGenericFindings(List.of(first, second), List.of(current, unavailable)));
    MavenElisionReportWriter.write(
        reverse, base.withGenericFindings(List.of(second, first), List.of(unavailable, current)));
    assertAll(
        () -> assertThat(Files.readString(forward)).isEqualTo(Files.readString(reverse)),
        () ->
            assertThat(MavenElisionReportWriter.render(MavenElisionReportWriter.read(forward)))
                .isEqualTo(
                    MavenElisionReportWriter.render(MavenElisionReportWriter.read(reverse))));
  }

  @Test
  void rejectsOldAndMalformedGenericShapes() throws IOException {
    final Path output = temp.resolve("invalid.json");
    MavenElisionReportWriter.write(output, snapshot(finding(), List.of()));
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode original = (ObjectNode) mapper.readTree(output.toFile());
    final ObjectNode missing = original.deepCopy();
    missing.remove("genericFindings");
    final ObjectNode old = original.deepCopy();
    old.putArray("advisoryReview");
    final ObjectNode badOutcome = original.deepCopy();
    ((ObjectNode) badOutcome.withArray("genericFindings").get(0)).put("outcome", "INVENTED");
    final ObjectNode missingNested = original.deepCopy();
    ((ObjectNode) missingNested.withArray("genericFindings").get(0).path("contributions").get(0))
        .remove("classifier");
    final ObjectNode badReason = original.deepCopy();
    ((com.fasterxml.jackson.databind.node.ArrayNode)
            badReason
                .withArray("genericFindings")
                .get(0)
                .path("codeAttribution")
                .get(0)
                .path("reasons"))
        .set(0, mapper.getNodeFactory().textNode("INVENTED"));
    final ObjectNode forgedCode = original.deepCopy();
    ((ObjectNode) forgedCode.withArray("genericFindings").get(0))
        .put("outcome", "DECLARED_CODE_ABSENT");
    final ObjectNode forgedPrerequisite = original.deepCopy();
    final ObjectNode prerequisiteRow =
        (ObjectNode) forgedPrerequisite.withArray("genericFindings").get(0);
    prerequisiteRow.put("outcome", "PREREQUISITES_ABSENT");
    prerequisiteRow.put("intent", "AUTO_VERIFY");
    prerequisiteRow.put("prerequisiteGroupStatus", "OMITTED");
    final ObjectNode missingCode = original.deepCopy();
    final ObjectNode missingCodeRow = (ObjectNode) missingCode.withArray("genericFindings").get(0);
    missingCodeRow.put("outcome", "DECLARED_CODE_ABSENT");
    missingCodeRow.put("intent", "AUTO_VERIFY");
    missingCodeRow.putArray("codeAttribution");
    final ObjectNode unresolvedProof = original.deepCopy();
    final ObjectNode unresolvedRow =
        (ObjectNode) unresolvedProof.withArray("genericFindings").get(0);
    unresolvedRow.put("outcome", "PREREQUISITES_ABSENT");
    unresolvedRow.put("intent", "AUTO_VERIFY");
    unresolvedRow.put("applicability", "UNRESOLVED");
    final ObjectNode wrongType = original.deepCopy();
    ((ObjectNode) wrongType.withArray("genericFindings").get(0)).put("aliases", false);
    assertAll(
        "malformed generic report rows are rejected",
        List.of(
                missing,
                old,
                badOutcome,
                missingNested,
                badReason,
                wrongType,
                forgedCode,
                forgedPrerequisite,
                missingCode,
                unresolvedProof)
            .stream()
            .map(
                invalid ->
                    (org.junit.jupiter.api.function.Executable)
                        () -> {
                          mapper.writeValue(output.toFile(), invalid);
                          assertThatThrownBy(() -> MavenElisionReportWriter.read(output))
                              .isInstanceOf(IOException.class);
                        }));
  }

  private GenericFindingAssessment finding() {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.5");
    final CodeReference reference = CodeReference.sourceFile("src/main/java/p/Example.java");
    final CodeClaim code = CodeClaim.declared(reference);
    final List<PrerequisiteClaim> pairs =
        List.of(
            new PrerequisiteClaim("org.example:first", "p.First"),
            new PrerequisiteClaim("org.example:second", "p.Second"));
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "GHSA-only",
            Set.of(),
            "org.example",
            "library",
            "jar",
            "",
            List.of(VersionCoverageClaim.affected("[1,2)"), VersionCoverageClaim.affected("[3,4)")),
            FieldValue.supplied(Set.of(code)),
            FieldValue.supplied(Set.copyOf(pairs)),
            MergePriority.MANUAL,
            AssessmentIntent.REVIEW_ONLY,
            "manual source",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.CVE_LIST,
                    "CVE-2026-12345",
                    URI.create("https://example.test/advisory"),
                    "a".repeat(64))));
    return new GenericFindingAssessment(
        "GHSA-only",
        Set.of("GHSA-only"),
        candidate,
        VersionApplicability.AFFECTED,
        Optional.of(AssessmentIntent.REVIEW_ONLY),
        ClaimGroupStatus.DECLARED,
        List.of(
            new CodeAttributionResolver.DeclarationResult(
                code,
                CodeAttributionResolver.Status.UNRESOLVED,
                Set.of(),
                List.of(CodeAttributionResolver.Reason.CLASS_NOT_FOUND))),
        List.of(),
        ClaimGroupStatus.DECLARED,
        pairs,
        List.of(VersionCoverageClaim.unresolvedRange("[4,5)", "unsupported")),
        Set.of("OVERRIDE"),
        Set.of("ENRICHED"),
        GenericFindingAssessment.Outcome.REVIEW_ONLY,
        "manual review",
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_UNCHANGED,
        List.of(contribution));
  }

  private MavenElisionReportSnapshot snapshot(
      final GenericFindingAssessment finding, final List<FindingSourceObservation> sources)
      throws IOException {
    final MavenProject project = new MavenProject();
    project.setGroupId("org.example");
    project.setArtifactId("consumer");
    project.setVersion("1");
    project.setFile(temp.resolve("pom.xml").toFile());
    final ElisionDecision decision = new ElisionDecision(Set.of(), Set.of(), Map.of(), Map.of(), 0);
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            new ElisionAnalysisModel.ArtifactViews(List.of(), false, List.of()),
            decision,
            decision,
            new ElisionAnalysisModel.AnalysisEvidence(
                new ClassUsageReport(List.of()), Optional.empty(), Map.of(), false, false, null),
            new TrimResult(
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                0,
                0L,
                0,
                new TrimExecutionEnvironment(21, Runtime.version().feature()),
                null),
            null,
            MediatedGraphReportTestSupport.emptyGraph("org.example:consumer:1"),
            MavenElisionPolicyIdentityTestSupport.emptyPolicy());
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment.Result(List.of(), List.of(finding), sources, false);
    return MavenElisionReportSnapshot.from(project, analysis, result);
  }
}
