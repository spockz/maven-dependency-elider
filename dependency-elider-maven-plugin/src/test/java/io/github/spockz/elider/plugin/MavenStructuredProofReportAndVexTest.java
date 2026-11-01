// WHY: Exercises live structured proof provenance through saved reports and both standard VEX
// schemas.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import io.github.spockz.elider.metadata.CycloneDxSbomGenerator;
import io.github.spockz.elider.metadata.OpenVexGenerator;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.ElisionDecision;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers persisted and standardized output for a production structured proof. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.UnitTestContainsTooManyAsserts"})
final class MavenStructuredProofReportAndVexTest {
  /** Group identifier shared by the production fixture and Maven project. */
  private static final String GROUP_ID = "org.example";

  /** JSON mapper used for standard VEX schemas and report mutations. */
  private static final ObjectMapper JSON = new ObjectMapper();

  /** Exact advisory identity shared by structured proof fixtures. */
  private static final String CVE_ID = "CVE-2025-12345";

  /** Deterministic timestamp supplied to standard VEX document generation. */
  private static final String GENERATED_AT = "2026-11-01T12:00:00Z";

  /** Temporary root for independent proof and report scenarios. */
  @TempDir private Path temporaryDirectory;

  @Test
  void liveProofRoundTripsSeparatelyAndSerializesBoundedProvenance() throws Exception {
    final Path run = temporaryDirectory.resolve("proof-run");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            run, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(run, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(run.resolve("trimmed.jar"));
    final MavenVulnerabilityAssessment.Result assessment =
        MavenStructuredProofScenario.assess(prepared, archives, trimmed, true);
    final ArtifactTrimRecord trimRecord =
        MavenStructuredProofScenario.trimRecord(prepared, archives.originalJar(), trimmed);
    final ElisionAnalysisModel.Analysis baseAnalysis =
        MavenCorroboratedSourceAnalysisFixtures.analysis(
            prepared.coordinate(), archives.originalJar(), List.of(trimRecord), false, false);
    final ArtifactCoordinate droppedCoordinate = ArtifactCoordinate.of(GROUP_ID, "unused", "0.9");
    final ElisionDecision analysisDecision =
        new ElisionDecision(
            Set.of(prepared.coordinate()), Set.of(droppedCoordinate), Map.of(), Map.of(), 0L);
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            new ElisionAnalysisModel.ArtifactViews(
                List.of(
                    new ElisionAnalysisModel.ArtifactSnapshot(
                        null, droppedCoordinate, archives.originalJar()),
                    new ElisionAnalysisModel.ArtifactSnapshot(
                        null, prepared.coordinate(), archives.originalJar())),
                true,
                List.of()),
            analysisDecision,
            analysisDecision,
            baseAnalysis.evidence(),
            baseAnalysis.trimResult(),
            null,
            MediatedGraphReportTestSupport.reportForOutputs(
                droppedCoordinate, prepared.coordinate(), GROUP_ID + ":consumer:1.0"));
    final MavenProject project = reportProject(run);
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(project, analysis, assessment);
    final Path report = run.resolve("elision-report.json");
    MavenElisionReportWriter.write(report, snapshot);
    final ArtifactFileRef inventory = ArtifactFileRef.fromPath(prepared.coordinate(), trimmed);
    final ElisionDecision decision =
        new ElisionDecision(Set.of(prepared.coordinate()), Set.of(), Map.of(), Map.of(), 0L);
    final Path bomPath = run.resolve("structured.cdx.json");
    new CycloneDxSbomGenerator()
        .write(
            bomPath,
            new CycloneDxSbomGenerator.RootIdentity(GROUP_ID, "consumer", "1.0", "Consumer"),
            List.of(inventory),
            decision,
            new CycloneDxSbomGenerator.DocumentMetadata(
                "urn:uuid:123e4567-e89b-12d3-a456-426614174000",
                1,
                Instant.parse(GENERATED_AT),
                "elider",
                "0.1.0"),
            List.of(trimRecord),
            List.of(assessment.attestations().getFirst(), assessment.attestations().getFirst()));
    final JsonNode bom = JSON.readTree(bomPath.toFile());
    final JsonNode openVex =
        JSON.readTree(
            new OpenVexGenerator()
                .generate(
                    new CycloneDxSbomGenerator.RootIdentity(
                        GROUP_ID, "consumer", "1.0", "Consumer"),
                    List.of(inventory),
                    List.of(
                        assessment.attestations().getFirst(), assessment.attestations().getFirst()),
                    new OpenVexGenerator.DocumentMetadata(
                        "https://example.invalid/vex/document",
                        "Dependency Elider",
                        "Tool",
                        Instant.parse(GENERATED_AT),
                        1)));
    final String cdxDetail =
        bom.path("vulnerabilities").get(0).path("analysis").path("detail").asText();
    final String vexDetail = openVex.path("statements").get(0).path("impact_statement").asText();

    Files.delete(prepared.cveRecord());
    Files.delete(archives.sourcesJar());
    Files.delete(archives.originalJar());
    Files.delete(trimmed);
    Files.deleteIfExists(prepared.cacheConfig().cacheDirectory().resolve("index.json"));
    Files.deleteIfExists(
        prepared
            .cacheConfig()
            .cacheDirectory()
            .resolve("cvelistV5/cves/2025/12xxx/CVE-2025-12345.json"));
    final MavenElisionReportSnapshot saved = MavenElisionReportWriter.read(report);
    final List<String> lines = MavenElisionReportWriter.render(saved);

    assertAll(
        "saved report and standard VEX detail preserve one live proof's provenance",
        () -> assertThat(saved.verifiedStructuredProofs()).hasSize(1),
        () -> assertThat(saved.sourceReviewFindings()).isEmpty(),
        () ->
            assertThat(saved.provenAbsentCves())
                .containsExactly(
                    new MavenElisionReportSnapshot.CveFinding(
                        CVE_ID, prepared.coordinate().toId())),
        () ->
            assertThat(lines)
                .anyMatch(
                    line ->
                        line.contains(
                            "Snapshot: last successful elide run at " + saved.generatedAt())),
        () ->
            assertThat(lines)
                .anyMatch(
                    line ->
                        line.contains("source archive SHA-256")
                            || line.contains("Sources artifact:")),
        () ->
            assertThat(lines)
                .anyMatch(line -> line.contains("CNA record SHA-256: " + prepared.cveDigest())),
        () -> assertThat(lines).anyMatch(line -> line.contains("conventional layout assumed=true")),
        () -> assertThat(bom.path("vulnerabilities")).hasSize(1),
        () ->
            assertThat(cdxDetail)
                .contains(
                    "class absence for the recorded CNA claims only",
                    "cveSourceSha256",
                    prepared.cveDigest(),
                    "sourcesArchiveSha256",
                    "compilerOptions",
                    "claimAttributions"),
        () -> assertThat(openVex.path("statements")).hasSize(1),
        () ->
            assertThat(vexDetail)
                .contains(
                    "does not independently validate vulnerability status",
                    "cnaAffectedEntryIdentity",
                    "rawScopeEvidence",
                    "claimAttributions"),
        () ->
            assertSchemaValid(
                Path.of("../elider-core/src/test/resources/schema/bom-1.6.schema.json"),
                SpecVersion.VersionFlag.V7,
                bom),
        () ->
            assertSchemaValid(
                Path.of("../elider-core/src/test/resources/schema/openvex-0.2.0.schema.json"),
                SpecVersion.VersionFlag.V202012,
                openVex));

    final JsonNode duplicatePayload = JSON.readTree(report.toFile());
    ((com.fasterxml.jackson.databind.node.ArrayNode)
            duplicatePayload.get("verifiedStructuredProofs"))
        .add(duplicatePayload.get("verifiedStructuredProofs").get(0).deepCopy());
    final Path duplicateReport = run.resolve("duplicate-proof-report.json");
    JSON.writeValue(duplicateReport.toFile(), duplicatePayload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(duplicateReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("duplicate verified structured proof");

    final JsonNode withoutFinding = JSON.readTree(report.toFile());
    ((com.fasterxml.jackson.databind.node.ArrayNode) withoutFinding.get("provenAbsentCves"))
        .removeAll();
    final Path inconsistentReport = run.resolve("proof-not-classified-report.json");
    JSON.writeValue(inconsistentReport.toFile(), withoutFinding);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(inconsistentReport))
        .isInstanceOf(IOException.class)
        .hasRootCauseMessage("Verified structured proof must be present in provenAbsentCves");
  }

  @Test
  void verifiedAndUnresolvedClaimsForDifferentExactComponentsRemainSeparate() throws Exception {
    final Path run = temporaryDirectory.resolve("proof-and-review-run");
    final MavenCorroboratedSourceScenario.Prepared prepared =
        MavenCorroboratedSourceScenario.prepareReproducibleClaim(
            run, List.of(MavenSourceCorrespondenceTestArtifacts.SOURCE_ENTRY), List.of());
    final MavenSourceCorrespondenceTestArtifacts.Archives archives =
        MavenSourceCorrespondenceTestArtifacts.write(run, false, false);
    final Path trimmed =
        MavenSourceCorrespondenceTestArtifacts.writeEmptyTrimmedJar(run.resolve("trimmed.jar"));
    final ArtifactTrimRecord trimRecord =
        MavenStructuredProofScenario.trimRecord(prepared, archives.originalJar(), trimmed);
    final ArtifactCoordinate unresolvedCoordinate =
        ArtifactCoordinate.of(
            prepared.coordinate().groupId(), prepared.coordinate().artifactId(), "3.0");
    final ElisionDecision decision =
        new ElisionDecision(
            Set.of(prepared.coordinate(), unresolvedCoordinate), Set.of(), Map.of(), Map.of(), 0L);
    final ElisionAnalysisModel.Analysis analysis =
        new ElisionAnalysisModel.Analysis(
            new ElisionAnalysisModel.ArtifactViews(
                List.of(
                    new ElisionAnalysisModel.ArtifactSnapshot(
                        null, prepared.coordinate(), archives.originalJar()),
                    new ElisionAnalysisModel.ArtifactSnapshot(
                        null, unresolvedCoordinate, archives.originalJar())),
                true,
                List.of()),
            decision,
            decision,
            new ElisionAnalysisModel.AnalysisEvidence(
                new io.github.spockz.elider.engine.ClassUsageReport(List.of()),
                java.util.Optional.empty(),
                Map.of(),
                false,
                false,
                null),
            new TrimResult(List.of(trimRecord), List.of(), List.of(), List.of(), 0, 0L, 0, null),
            null,
            MediatedGraphReportTestSupport.reportForTrimmedOutputAndRetainedComponent(
                prepared.coordinate(), unresolvedCoordinate, GROUP_ID + ":consumer:1.0"));
    final MavenVulnerabilityAssessment.Result assessment =
        MavenStructuredProofScenario.assess(prepared, archives, analysis, true);
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(reportProject(run), analysis, assessment);
    final Path report = run.resolve("coexisting-proof-and-review.json");
    MavenElisionReportWriter.write(report, snapshot);
    final MavenElisionReportSnapshot saved = MavenElisionReportWriter.read(report);
    final List<String> lines = MavenElisionReportWriter.render(saved);

    assertAll(
        "production assessment keeps separate exact component and claim identities",
        () -> assertThat(assessment.attestations()).hasSize(1),
        () -> assertThat(assessment.matchedSourceClaims()).hasSize(2),
        () -> assertThat(saved.verifiedStructuredProofs()).hasSize(1),
        () -> assertThat(saved.sourceReviewFindings()).hasSize(1),
        () ->
            assertThat(saved.verifiedStructuredProofs().getFirst().coordinate())
                .isEqualTo(prepared.coordinate().toString()),
        () ->
            assertThat(saved.sourceReviewFindings().getFirst().coordinate())
                .isEqualTo(unresolvedCoordinate.toString()),
        () ->
            assertThat(saved.sourceReviewFindings().getFirst().applicability())
                .isEqualTo(OsvPackageApplicability.Status.UNRESOLVED),
        () ->
            assertThat(lines).anyMatch(line -> line.contains("Verified structured source proofs")),
        () ->
            assertThat(lines)
                .anyMatch(line -> line.contains("Structured source claims (review only")));
  }

  private MavenProject reportProject(final Path baseDirectory) throws IOException {
    Files.createDirectories(baseDirectory);
    final MavenProject project = new MavenProject();
    project.setGroupId(GROUP_ID);
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setFile(new File(baseDirectory.resolve("pom.xml").toString()));
    return project;
  }

  private void assertSchemaValid(
      final Path schemaPath, final SpecVersion.VersionFlag version, final JsonNode document)
      throws IOException {
    final byte[] schema = Files.readAllBytes(schemaPath);
    final JsonSchemaFactory factory = JsonSchemaFactory.getInstance(version);
    assertThat(factory.getSchema(JSON.readTree(schema)).validate(document)).isEmpty();
  }
}
