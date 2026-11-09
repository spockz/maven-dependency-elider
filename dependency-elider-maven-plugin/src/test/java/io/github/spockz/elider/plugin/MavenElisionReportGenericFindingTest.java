/* WHY: Ensures saved generic findings replay captured decisions without live source inputs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
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
import io.github.spockz.elider.model.GenericFindingReconciler;
import io.github.spockz.elider.model.GenericVulnerabilityFinding;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.OmittedCodeProof;
import io.github.spockz.elider.model.PreconditionClassInventory;
import io.github.spockz.elider.model.PreconditionProof;
import io.github.spockz.elider.model.PrerequisiteAbsenceAttribution;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteMemberObservation;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.PrerequisiteProofResult;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.StreamSupport;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Exercises persisted generic reports and real proof output. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidDuplicateLiterals",
  "PMD.TooManyMethods"
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
                    "\"catalogAdoptions\"",
                    "GHSA-only",
                    "[1,2)",
                    "[3,4)",
                    "src/main/java/p/Example.java",
                    "cache unavailable",
                    "refresh failed",
                    "old-revision",
                    "retained snapshot",
                    "record warning",
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
                    "Sources: [CVE_LIST, manual source]",
                    "CVE Sources:\n",
                    "OSV CURRENT",
                    "CVE_LIST STALE",
                    "CACHE UNAVAILABLE",
                    "Source diagnostics are in the JSON snapshot"),
        () ->
            assertThat(rendered)
                .doesNotContain(
                    "https://example.test/advisory",
                    "a".repeat(64),
                    "AdvisoryProvenance[",
                    "FieldValue[",
                    "VersionCoverageClaim[",
                    "Source observations:",
                    "record warning",
                    "retained snapshot",
                    "revision:",
                    "last success:",
                    "contributions:"),
        () -> {
          final String predicted =
              String.join(
                  "\n", MavenElisionReportGenericRenderer.render(List.of(finding), sources, true));
          assertThat(predicted)
              .contains(
                  "Analysis only",
                  "GHSA-only",
                  "Sources: [CVE_LIST, manual source]",
                  "refresh failed")
              .doesNotContain("https://example.test/advisory", "FieldValue[", "revision:");
        });
  }

  // Validation precedes writing and replaying the same proof fixture.
  @Test
  @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
  void proofEvidenceRoundTripsAllOfAndMixedProviderObservationsOffline()
      throws IOException, ReflectiveOperationException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.5");
    final ArtifactCoordinate presentProvider =
        ArtifactCoordinate.of("org.example", "present-provider", "1.0");
    final ArtifactCoordinate droppedProvider =
        ArtifactCoordinate.of("org.example", "dropped-provider", "1.0");
    final ArtifactCoordinate trimmedProvider =
        ArtifactCoordinate.of("org.example", "trimmed-provider", "1.0");
    final Path candidateBaselinePath = providerJar("proof-candidate-baseline.jar");
    final Path candidateFinalPath = providerJar("proof-candidate-final.jar");
    final Path presentBaselinePath = providerJar("proof-present-baseline.jar", "proof/Present");
    final Path presentFinalPath = providerJar("proof-present-final.jar", "proof/Present");
    final Path droppedBaselinePath = providerJar("proof-dropped-baseline.jar", "proof/Absent");
    final Path trimmedBaselinePath = providerJar("proof-trimmed-baseline.jar", "proof/Absent");
    final Path trimmedFinalPath = providerJar("proof-trimmed-final.jar");
    final PrerequisiteClaim present =
        new PrerequisiteClaim("org.example:present-provider", "proof.Present");
    final PrerequisiteClaim absent =
        new PrerequisiteClaim("org.example:dropped-provider", "proof.Absent");
    final PrerequisiteGroup group =
        new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(present, absent));
    final ArtifactCoordinate bridgeCandidate =
        ArtifactCoordinate.of("org.example", "alias-bridge", "1.0");
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-24680",
            Set.of("POM-ALIAS"),
            candidate.groupId(),
            candidate.artifactId(),
            candidate.type(),
            candidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "manual:all-of-proof",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.POM,
                    "all-of-proof",
                    URI.create("https://example.test/advisory"),
                    null)),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final VulnerabilityFindingContribution linkedOsvContribution =
        new VulnerabilityFindingContribution(
            "GHSA-25qh-j22f-pwp8",
            Set.of("OSV-ALIAS"),
            candidate.groupId(),
            candidate.artifactId(),
            candidate.type(),
            candidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "osv:alias-linked-proof",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.OSV,
                    "GHSA-25qh-j22f-pwp8",
                    URI.create("https://example.test/ghsa"),
                    null)),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final VulnerabilityFindingContribution aliasBridge =
        new VulnerabilityFindingContribution(
            "POM-ALIAS",
            Set.of("OSV-ALIAS"),
            bridgeCandidate.groupId(),
            bridgeCandidate.artifactId(),
            bridgeCandidate.type(),
            bridgeCandidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.AUTOMATIC,
            AssessmentIntent.AUTO_VERIFY,
            "alias:bridge",
            Set.of(),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final List<VulnerabilityFindingContribution> allContributions =
        List.of(contribution, aliasBridge, linkedOsvContribution);
    final GenericFindingReconciler.Result reconciliation =
        GenericFindingReconciler.reconcile(allContributions);
    final GenericVulnerabilityFinding merged =
        reconciliation.findings().stream()
            .filter(
                row ->
                    row.contributions().stream()
                        .anyMatch(
                            value ->
                                value.groupId().equals(candidate.groupId())
                                    && value.artifactId().equals(candidate.artifactId())))
            .findFirst()
            .orElseThrow();
    final List<VulnerabilityFindingContribution> linkedContributions = merged.contributions();
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.complete(
            List.of(
                provider(candidate, candidateBaselinePath),
                provider(presentProvider, presentBaselinePath),
                provider(droppedProvider, droppedBaselinePath),
                provider(trimmedProvider, trimmedBaselinePath)));
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(
            List.of(
                provider(candidate, candidateFinalPath),
                provider(presentProvider, presentFinalPath),
                provider(trimmedProvider, trimmedFinalPath)));
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(merged, candidate, baseline, actualFinal);
    final GenericFindingAssessment assessment =
        assessmentRow(
            candidate,
            "CVE-2026-24680",
            Set.of("CVE-2026-24680", "GHSA-25qh-j22f-pwp8", "POM-ALIAS", "OSV-ALIAS"),
            linkedContributions,
            group,
            proof);
    assertAll(
        "proof validation requires one canonical alias component matching its saved row",
        () ->
            assertProofRejected(
                assessmentRow(candidate, "GHSA-25qh-j22f-pwp8", assessment, group, proof),
                "saved canonical mismatch"),
        () -> {
          assertAll(
              "the reconciled component key includes every GATC field",
              () ->
                  assertWrongComponentRejected(
                      candidate,
                      contribution,
                      linkedOsvContribution,
                      ArtifactCoordinate.of("org.other", "library", "1.5"),
                      group,
                      proof),
              () ->
                  assertWrongComponentRejected(
                      candidate,
                      contribution,
                      linkedOsvContribution,
                      ArtifactCoordinate.of("org.example", "other-library", "1.5"),
                      group,
                      proof),
              () ->
                  assertWrongComponentRejected(
                      candidate,
                      contribution,
                      linkedOsvContribution,
                      new ArtifactCoordinate(
                          candidate.groupId(),
                          candidate.artifactId(),
                          candidate.version(),
                          "test-jar",
                          "",
                          candidate.scope()),
                      group,
                      proof),
              () ->
                  assertWrongComponentRejected(
                      candidate,
                      contribution,
                      linkedOsvContribution,
                      new ArtifactCoordinate(
                          candidate.groupId(),
                          candidate.artifactId(),
                          candidate.version(),
                          candidate.type(),
                          "tests",
                          candidate.scope()),
                      group,
                      proof));
        },
        () -> {
          final VulnerabilityFindingContribution outsideAlias =
              copyContribution(
                  linkedOsvContribution, "GHSA-outside-class", Set.of(), candidate, group);
          assertProofRejected(
              assessmentRow(
                  candidate,
                  assessment.vulnerabilityId(),
                  assessment.aliases(),
                  List.of(contribution, outsideAlias),
                  group,
                  proof),
              "component contribution falls outside the persisted alias class");
        },
        () -> {
          final VulnerabilityFindingContribution competingCve =
              copyContribution(
                  linkedOsvContribution,
                  "CVE-2026-99999",
                  linkedOsvContribution.aliases(),
                  candidate,
                  group);
          assertProofRejected(
              assessmentRow(
                  candidate,
                  "CVE-2026-24680",
                  Set.of(
                      "CVE-2026-24680",
                      "CVE-2026-99999",
                      "GHSA-25qh-j22f-pwp8",
                      "POM-ALIAS",
                      "OSV-ALIAS"),
                  List.of(contribution, competingCve),
                  group,
                  proof),
              "ambiguous competing CVE aliases");
        },
        () -> {
          final PrerequisiteGroup changedGroup =
              new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, group.members());
          final List<VulnerabilityFindingContribution> changedGroups =
              linkedContributions.stream()
                  .map(
                      value ->
                          copyContribution(
                              value,
                              value.vulnerabilityId(),
                              value.aliases(),
                              candidate,
                              changedGroup))
                  .toList();
          assertProofRejected(
              assessmentRow(
                  candidate,
                  assessment.vulnerabilityId(),
                  assessment.aliases(),
                  changedGroups,
                  changedGroup,
                  proof),
              "saved proof operator differs from the reconciled source group");
        });
    final Path output = temp.resolve("prerequisite-proof-report.json");

    final MavenElisionReportSnapshot savedSnapshot =
        snapshot(assessment, List.of()).withGenericFindings(List.of(assessment), List.of());
    MavenElisionReportWriter.write(output, savedSnapshot);
    final ObjectNode json = (ObjectNode) new ObjectMapper().readTree(output.toFile());
    final JsonNode savedProofRow =
        StreamSupport.stream(json.withArray("genericFindings").spliterator(), false)
            .filter(row -> "CVE-2026-24680".equals(row.path("vulnerabilityId").asText()))
            .filter(row -> "library".equals(row.path("candidate").path("artifactId").asText()))
            .findFirst()
            .orElseThrow();
    final JsonNode serializedProof = savedProofRow.get("prerequisiteProof");

    assertAll(
        "saved proof retains the atomic group and provider causes after source archives disappear",
        () ->
            assertAll(
                "the source proof records one present member and mixed causes for the absent"
                    + " member",
                () -> assertThat(proof.groups()).hasSize(1),
                () -> assertThat(reconciliation.findings()).hasSize(2),
                () -> assertThat(merged.vulnerabilityId()).isEqualTo("CVE-2026-24680"),
                () ->
                    assertThat(merged.aliases())
                        .contains(
                            "CVE-2026-24680", "GHSA-25qh-j22f-pwp8", "POM-ALIAS", "OSV-ALIAS"),
                () -> assertThat(linkedContributions).doesNotContain(aliasBridge),
                () -> assertThat(proof.groups().getFirst().group()).isEqualTo(group),
                () ->
                    assertThat(proof.groups().getFirst().attribution())
                        .isEqualTo(PrerequisiteAbsenceAttribution.MIXED),
                () ->
                    assertThat(proof.groups().getFirst().members())
                        .extracting(PrerequisiteProofResult.MemberOutcome::claim)
                        .containsExactly(absent, present),
                () ->
                    assertThat(proof.groups().getFirst().members().getFirst().attribution())
                        .isEqualTo(PrerequisiteAbsenceAttribution.MIXED),
                () ->
                    assertThat(proof.groups().getFirst().members().getFirst().providers())
                        .extracting(PrerequisiteProofResult.ProviderOutcome::attribution)
                        .containsExactlyInAnyOrder(
                            PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY,
                            PrerequisiteAbsenceAttribution.TRIMMED_CLASS),
                () ->
                    assertThat(proof.groups().getFirst().members().get(1).attribution())
                        .isEqualTo(PrerequisiteAbsenceAttribution.PRESENT),
                () ->
                    assertThat(proof.attestation().impactDetail())
                        .contains("at least one member is absent", "proof.Absent")
                        .doesNotContain("proof.Present is absent")),
        () ->
            assertAll(
                "serialized proof is detached evidence, not a re-created attestation",
                () -> assertThat(serializedProof).isNotNull(),
                () ->
                    assertSerializedProof(
                        serializedProof,
                        new SerializedProofContext(
                            candidate,
                            candidateFinalPath,
                            baseline,
                            actualFinal,
                            new ProviderEvidencePaths(
                                presentProvider,
                                droppedProvider,
                                trimmedProvider,
                                presentBaselinePath,
                                presentFinalPath,
                                droppedBaselinePath,
                                trimmedBaselinePath,
                                trimmedFinalPath)))),
        () -> {
          Files.delete(candidateBaselinePath);
          Files.delete(candidateFinalPath);
          Files.delete(presentBaselinePath);
          Files.delete(presentFinalPath);
          Files.delete(droppedBaselinePath);
          Files.delete(trimmedBaselinePath);
          Files.delete(trimmedFinalPath);
          final MavenElisionReportSnapshot replayed = MavenElisionReportWriter.read(output);
          final List<String> messages = new ArrayList<>();
          final MavenProject project = new MavenProject();
          project.setGroupId("org.example");
          project.setArtifactId("consumer");
          project.setVersion("1");
          project.setFile(temp.resolve("pom.xml").toFile());
          final ReportMojo reportMojo = ReportMojoTestSupport.mojo(output, project, messages);
          reportMojo.execute();
          final String rendered = String.join("\n", messages);
          final GenericFindingAssessment sourceFinding = assessment;
          final GenericFindingAssessment replayedFinding =
              replayed.genericFindings().stream()
                  .filter(
                      value ->
                          "CVE-2026-24680".equals(value.vulnerabilityId())
                              && value.candidate().equals(candidate)
                              && value.outcome()
                                  == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT)
                  .findFirst()
                  .orElseThrow();
          assertAll(
              () -> assertThat(replayedFinding.prerequisiteProof()).isEmpty(),
              () -> assertThat(sourceFinding.prerequisiteProofEvidence()).isPresent(),
              () ->
                  assertThat(replayedFinding.prerequisiteProofEvidence())
                      .isEqualTo(sourceFinding.prerequisiteProofEvidence()),
              () ->
                  assertThat(rendered)
                      .contains(
                          "PREREQUISITES_ABSENT",
                          "ALL_OF",
                          "MIXED",
                          "proof.Absent",
                          "PRESENT",
                          "ABSENT")
                      .doesNotContain("proof.Present is absent"));
        });
  }

  @Test
  void incompleteBaselineReasonSurvivesDetachedProofReportReplay() throws IOException {
    final ArtifactCoordinate candidate =
        ArtifactCoordinate.of("org.example", "unknown-base", "1.5");
    final Path candidatePath = providerJar("unknown-baseline-candidate.jar");
    final PrerequisiteClaim claim = new PrerequisiteClaim("org.example:provider", "proof.Optional");
    final PrerequisiteGroup group =
        new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(claim));
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-24682",
            Set.of(),
            candidate.groupId(),
            candidate.artifactId(),
            candidate.type(),
            candidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "manual:unknown-baseline",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.POM,
                    "unknown-baseline",
                    URI.create("https://example.test/unknown-baseline"),
                    null)),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(contribution));
    final PreconditionClassInventory.Provider candidateProvider =
        provider(candidate, candidatePath);
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(
            finding,
            candidate,
            PreconditionClassInventory.incomplete(
                List.of(candidateProvider), "baseline class providers were unavailable"),
            PreconditionClassInventory.complete(List.of(candidateProvider)));
    final GenericFindingAssessment assessment =
        assessmentRow(candidate, contribution, group, proof);
    final Path output = temp.resolve("unknown-baseline-proof.json");
    MavenElisionReportWriter.write(output, snapshot(assessment, List.of()));
    Files.delete(candidatePath);
    final GenericFindingAssessment replayed =
        MavenElisionReportWriter.read(output).genericFindings().getFirst();

    assertAll(
        "baseline uncertainty remains descriptive while final class absence is replayable",
        () ->
            assertThat(proof.groups().getFirst().members().getFirst().attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN),
        () -> assertThat(replayed.prerequisiteProof()).isEmpty(),
        () -> assertThat(replayed.prerequisiteProofEvidence()).isPresent(),
        () ->
            assertThat(replayed.prerequisiteProofEvidence().orElseThrow().baselineDetail())
                .isEqualTo("baseline class providers were unavailable"),
        () ->
            assertThat(
                    replayed
                        .prerequisiteProofEvidence()
                        .orElseThrow()
                        .groups()
                        .getFirst()
                        .members()
                        .getFirst()
                        .attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN),
        () ->
            assertThat(
                    replayed
                        .prerequisiteProofEvidence()
                        .orElseThrow()
                        .groups()
                        .getFirst()
                        .members()
                        .getFirst()
                        .state())
                .isEqualTo(PrerequisiteMemberObservation.State.ABSENT));
  }

  @Test
  void baselineDetailPreservesPresentProviderInAllOfReplay() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "all-of-base", "1.5");
    final ArtifactCoordinate presentOwner = ArtifactCoordinate.of("org.example", "present", "1.0");
    final Path candidatePath = providerJar("all-of-baseline-detail-candidate.jar");
    final Path presentPath = providerJar("all-of-baseline-detail-present.jar", "proof/Present");
    final PrerequisiteClaim present = new PrerequisiteClaim("org.example:present", "proof.Present");
    final PrerequisiteClaim unknown = new PrerequisiteClaim("org.example:unknown", "proof.Unknown");
    final PrerequisiteGroup group =
        new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(present, unknown));
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-24683",
            Set.of(),
            candidate.groupId(),
            candidate.artifactId(),
            candidate.type(),
            candidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "manual:baseline-detail-all-of",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.POM,
                    "baseline-detail-all-of",
                    URI.create("https://example.test/baseline-detail-all-of"),
                    null)),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final GenericVulnerabilityFinding finding =
        GenericVulnerabilityFinding.merge(List.of(contribution));
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(
            finding,
            candidate,
            PreconditionClassInventory.incomplete(
                List.of(provider(candidate, candidatePath)), "baseline inventory unavailable"),
            PreconditionClassInventory.complete(
                List.of(provider(candidate, candidatePath), provider(presentOwner, presentPath))));
    final Path output = temp.resolve("baseline-detail-all-of.json");
    MavenElisionReportWriter.write(
        output, snapshot(assessmentRow(candidate, contribution, group, proof), List.of()));
    final GenericFindingAssessment replayed =
        MavenElisionReportWriter.read(output).genericFindings().getFirst();
    final List<PrerequisiteProofEvidence.MemberEvidence> members =
        replayed.prerequisiteProofEvidence().orElseThrow().groups().getFirst().members();

    assertAll(
        "baseline uncertainty applies only to absent members, preserving final PRESENT evidence",
        () -> assertThat(proof.baselineDetail()).isEqualTo("baseline inventory unavailable"),
        () -> assertThat(replayed.prerequisiteProof()).isEmpty(),
        () ->
            assertThat(
                    replayed.prerequisiteProofEvidence().orElseThrow().groups().getFirst().group())
                .isEqualTo(group),
        () -> assertThat(members).hasSize(2),
        () ->
            assertThat(members)
                .anySatisfy(
                    member -> {
                      assertThat(member.claim()).isEqualTo(present);
                      assertThat(member.state())
                          .isEqualTo(PrerequisiteMemberObservation.State.PRESENT);
                      assertThat(member.providers())
                          .singleElement()
                          .satisfies(
                              provider -> {
                                assertThat(provider.attribution())
                                    .isEqualTo(PrerequisiteAbsenceAttribution.PRESENT);
                                assertThat(provider.finalPath()).isEqualTo(presentPath);
                              });
                    }),
        () ->
            assertThat(members)
                .anySatisfy(
                    member -> {
                      assertThat(member.claim()).isEqualTo(unknown);
                      assertThat(member.state())
                          .isEqualTo(PrerequisiteMemberObservation.State.ABSENT);
                      assertThat(member.attribution())
                          .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN);
                      assertThat(member.providers()).isEmpty();
                    }));
  }

  private static void assertSerializedProof(
      final JsonNode proof, final SerializedProofContext context) {
    final ArtifactCoordinate candidate = context.candidate();
    final Path candidateFinalPath = context.candidateFinalPath();
    final PreconditionClassInventory baseline = context.baseline();
    final PreconditionClassInventory actualFinal = context.actualFinal();
    final ProviderEvidencePaths providerPaths = context.providers();
    assertThat(proof).isNotNull();
    assertThat(proof.path("candidate").asText()).isEqualTo(candidate.toString());
    assertThat(proof.path("finalInventoryFingerprint").asText())
        .isEqualTo(actualFinal.fingerprint());
    final JsonNode groups = proof.path("groups");
    assertThat(groups).hasSize(1);
    final JsonNode group = groups.get(0);
    assertThat(group.path("operator").asText()).isEqualTo("ALL_OF");
    assertThat(group.path("attribution").asText()).isEqualTo("MIXED");
    final JsonNode members = group.path("members");
    assertThat(members).hasSize(2);
    final JsonNode absent = members.get(0);
    assertAll(
        "the absent ALL_OF member binds both provider causes independently",
        () ->
            assertThat(absent.path("claim").path("requiresDependency").asText())
                .isEqualTo("org.example:dropped-provider"),
        () ->
            assertThat(absent.path("claim").path("requiresClass").asText())
                .isEqualTo("proof.Absent"),
        () -> assertThat(absent.path("state").asText()).isEqualTo("ABSENT"),
        () -> assertThat(absent.path("attribution").asText()).isEqualTo("MIXED"),
        () -> {
          final JsonNode providers = absent.path("providers");
          assertThat(providers).hasSize(2);
          assertProviderObservation(
              providers,
              baseline,
              actualFinal,
              providerPaths.droppedProvider(),
              providerPaths.droppedBaselinePath(),
              null,
              "ELIDED_DEPENDENCY");
          assertProviderObservation(
              providers,
              baseline,
              actualFinal,
              providerPaths.trimmedProvider(),
              providerPaths.trimmedBaselinePath(),
              providerPaths.trimmedFinalPath(),
              "TRIMMED_CLASS");
        });
    final JsonNode present = members.get(1);
    assertAll(
        "a present ALL_OF member remains visible in captured proof evidence",
        () -> assertThat(present.path("state").asText()).isEqualTo("PRESENT"),
        () -> assertThat(present.path("attribution").asText()).isEqualTo("PRESENT"),
        () ->
            assertProviderObservation(
                present.path("providers"),
                baseline,
                actualFinal,
                providerPaths.presentProvider(),
                providerPaths.presentBaselinePath(),
                providerPaths.presentFinalPath(),
                "PRESENT"));
    final PreconditionClassInventory.Provider candidateFinal =
        actualFinal.providers().stream()
            .filter(value -> candidate.equals(value.coordinate()))
            .findFirst()
            .orElseThrow();
    assertThat(proof.path("affectedArtifactPath").asText())
        .isEqualTo(candidateFinalPath.toString());
    assertThat(proof.path("postElisionSha256").asText()).isEqualTo(candidateFinal.sha256());
  }

  private static void assertProviderObservation(
      final JsonNode providers,
      final PreconditionClassInventory baseline,
      final PreconditionClassInventory actualFinal,
      final ArtifactCoordinate coordinate,
      final Path baselinePath,
      final Path finalPath,
      final String cause) {
    final JsonNode row =
        StreamSupport.stream(providers.spliterator(), false)
            .filter(value -> value.path("coordinate").asText().equals(coordinate.toString()))
            .findFirst()
            .orElseThrow();
    final String baselineDigest = inventoryDigest(baseline, baselinePath);
    final String finalDigest = inventoryDigest(actualFinal, finalPath);
    assertAll(
        () -> assertThat(row.path("kind").asText()).isEqualTo("DEPENDENCY_ARCHIVE"),
        () -> assertThat(row.path("coordinate").asText()).isEqualTo(coordinate.toString()),
        () ->
            assertThat(row.path("baselinePath").isNull() ? null : row.path("baselinePath").asText())
                .isEqualTo(baselinePath == null ? null : baselinePath.toString()),
        () ->
            assertThat(
                    row.path("baselineSha256").isNull()
                        ? null
                        : row.path("baselineSha256").asText())
                .isEqualTo(baselineDigest),
        () ->
            assertThat(row.path("finalPath").isNull() ? null : row.path("finalPath").asText())
                .isEqualTo(finalPath == null ? null : finalPath.toString()),
        () ->
            assertThat(row.path("finalSha256").isNull() ? null : row.path("finalSha256").asText())
                .isEqualTo(finalDigest),
        () -> assertThat(row.path("attribution").asText()).isEqualTo(cause));
  }

  private static String inventoryDigest(
      final PreconditionClassInventory inventory, final Path path) {
    return path == null
        ? null
        : inventory.providers().stream()
            .filter(value -> value.path().equals(path))
            .map(PreconditionClassInventory.Provider::sha256)
            .findFirst()
            .orElse(null);
  }

  @Test
  void rejectsMalformedDetachedPrerequisiteProofEvidence() throws IOException {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode validPayload = detachedProofPayload(mapper);
    assertAll(
        "detached proof evidence requires a unique, complete, well-typed binding",
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "missing-final-fingerprint",
                "finalInventoryFingerprint",
                proof -> proof.remove("finalInventoryFingerprint")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "missing-component-binding",
                "candidate",
                proof -> proof.remove("candidate")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "empty-members",
                "groups[0]",
                proof -> proofMembers(proof).removeAll()),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "invalid-member-state",
                "state",
                proof -> ((ObjectNode) proofMembers(proof).get(0)).put("state", "MAYBE")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "invalid-member-cause",
                "attribution",
                proof -> ((ObjectNode) proofMembers(proof).get(0)).put("attribution", "MAYBE")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "invalid-provider-cause",
                "attribution",
                proof -> {
                  final ArrayNode providers =
                      ((ObjectNode) proofMembers(proof).get(0)).withArray("providers");
                  ((ObjectNode) providers.get(0)).put("attribution", "MAYBE");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "invalid-group-operator",
                "operator",
                proof -> ((ObjectNode) proofGroups(proof).get(0)).put("operator", "XOR")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "duplicate-group",
                "duplicate",
                proof -> {
                  final ObjectNode duplicate = ((ObjectNode) proofGroups(proof).get(0)).deepCopy();
                  proofGroups(proof).add(duplicate);
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "duplicate-provider-identity-with-distinct-scope-and-path",
                "duplicate dependency provider identity",
                proof -> {
                  final ArrayNode providers =
                      ((ObjectNode) proofMembers(proof).get(0)).withArray("providers");
                  final ObjectNode duplicate = ((ObjectNode) providers.get(0)).deepCopy();
                  final String coordinate = duplicate.path("coordinate").asText();
                  duplicate.put(
                      "coordinate",
                      coordinate.substring(0, coordinate.lastIndexOf(" (")) + " (runtime)");
                  duplicate.put("baselinePath", "/tmp/duplicate-scope-provider.jar");
                  providers.add(duplicate);
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "operator-differs-from-selected-source-group",
                "groups[0].operator",
                proof -> ((ObjectNode) proofGroups(proof).get(0)).put("operator", "ALL_OF")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "provider-cause-conflicts-with-member",
                "providers[0]",
                proof -> proofProvider(proof).put("attribution", "TRIMMED_CLASS")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "group-cause-conflicts-with-member",
                "groups[0].attribution",
                proof ->
                    ((ObjectNode) proofGroups(proof).get(0)).put("attribution", "TRIMMED_CLASS")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "repeated-claim-has-conflicting-provider-outcome",
                "groups[1].members[0]",
                proof -> {
                  final ObjectNode repeatedGroup =
                      ((ObjectNode) proofGroups(proof).get(0)).deepCopy();
                  repeatedGroup.put("operator", "ALL_OF");
                  repeatedGroup.put("attribution", "TRIMMED_CLASS");
                  ((ObjectNode) repeatedGroup.withArray("members").get(0))
                      .put("attribution", "TRIMMED_CLASS");
                  final ObjectNode repeatedMember =
                      (ObjectNode) repeatedGroup.withArray("members").get(0);
                  final ObjectNode repeatedProvider =
                      (ObjectNode) repeatedMember.withArray("providers").get(0);
                  repeatedProvider.put("attribution", "TRIMMED_CLASS");
                  repeatedProvider.put("finalPath", "/tmp/repeated-provider-final.jar");
                  repeatedProvider.put("finalSha256", "a".repeat(64));
                  proofGroups(proof).add(repeatedGroup);
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "trimmed-class-provider-missing-final-archive",
                "providers[0]",
                proof -> proofProvider(proof).put("attribution", "TRIMMED_CLASS")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "elided-provider-has-final-archive",
                "providers[0]",
                proof -> {
                  final ObjectNode provider = proofProvider(proof);
                  provider.put("finalPath", provider.path("baselinePath").asText());
                  provider.put("finalSha256", provider.path("baselineSha256").asText());
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "aggregate-cause-on-provider-row",
                "providers[0]",
                proof -> proofProvider(proof).put("attribution", "MIXED")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "application-provider-with-dependency-coordinate",
                "providers[0].coordinate",
                proof -> proofProvider(proof).put("kind", "APPLICATION_CLASS_FILE")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "dependency-provider-without-coordinate",
                "providers[0].coordinate",
                proof -> proofProvider(proof).putNull("coordinate")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "unknown-dependency-provider-is-impossible",
                "providers[0]",
                proof -> {
                  proofProvider(proof).put("attribution", "UNKNOWN");
                  proofMember(proof).put("attribution", "UNKNOWN");
                  proofGroup(proof).put("attribution", "UNKNOWN");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "trimmed-class-must-change-provider-digest",
                "providers[0]",
                proof -> {
                  final ObjectNode provider = proofProvider(proof);
                  provider.put("attribution", "TRIMMED_CLASS");
                  provider.put("finalPath", "/tmp/same-digest-provider-final.jar");
                  provider.put("finalSha256", provider.path("baselineSha256").asText());
                  proofMember(proof).put("attribution", "TRIMMED_CLASS");
                  proofGroup(proof).put("attribution", "TRIMMED_CLASS");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "baseline-detail-requires-unknown-member-without-providers",
                "groups[0].members[0].attribution",
                proof -> {
                  ((ArrayNode)
                          proof
                              .withArray("groups")
                              .get(0)
                              .withArray("members")
                              .get(0)
                              .get("providers"))
                      .removeAll();
                  proof.put("baselineDetail", "baseline inventory was incomplete");
                  proofMember(proof).put("attribution", "ALREADY_ABSENT");
                  proofGroup(proof).put("attribution", "ALREADY_ABSENT");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "baseline-detail-cannot-claim-provider-transition-for-absent-member",
                "groups[0].members[0].attribution",
                proof -> proof.put("baselineDetail", "baseline inventory was incomplete")),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "complete-baseline-cannot-mark-empty-provider-set-unknown",
                "groups[0].members[0].attribution",
                proof -> {
                  ((ArrayNode)
                          proof
                              .withArray("groups")
                              .get(0)
                              .withArray("members")
                              .get(0)
                              .get("providers"))
                      .removeAll();
                  proofMember(proof).put("attribution", "UNKNOWN");
                  proofGroup(proof).put("attribution", "UNKNOWN");
                }),
        () ->
            assertAcceptedProof(
                mapper,
                validPayload,
                "unknown-application-provider",
                proof -> {
                  final ObjectNode provider = proofProvider(proof);
                  provider.put("kind", "APPLICATION_CLASS_FILE");
                  provider.putNull("coordinate");
                  provider.put("attribution", "UNKNOWN");
                  proofMember(proof).put("attribution", "UNKNOWN");
                  proofGroup(proof).put("attribution", "UNKNOWN");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "unknown-application-provider-cannot-change-path",
                "providers[0]",
                proof -> {
                  final ObjectNode provider = proofProvider(proof);
                  provider.put("kind", "APPLICATION_CLASS_FILE");
                  provider.putNull("coordinate");
                  provider.put("attribution", "UNKNOWN");
                  provider.put("finalPath", "/tmp/application-provider-final");
                  provider.put("finalSha256", "a".repeat(64));
                  proofMember(proof).put("attribution", "UNKNOWN");
                  proofGroup(proof).put("attribution", "UNKNOWN");
                }),
        () ->
            assertMalformedProof(
                mapper,
                validPayload,
                "unknown-application-provider-cannot-have-identical-snapshot-bytes",
                "providers[0]",
                proof -> {
                  final ObjectNode provider = proofProvider(proof);
                  provider.put("kind", "APPLICATION_CLASS_FILE");
                  provider.putNull("coordinate");
                  provider.put("attribution", "UNKNOWN");
                  provider.put("finalPath", provider.path("baselinePath").asText());
                  provider.put("finalSha256", provider.path("baselineSha256").asText());
                  proofMember(proof).put("attribution", "UNKNOWN");
                  proofGroup(proof).put("attribution", "UNKNOWN");
                }),
        () ->
            assertAcceptedProof(
                mapper,
                validPayload,
                "already-absent-without-provider-rows",
                proof -> {
                  ((ArrayNode) proofMembers(proof).get(0).get("providers")).removeAll();
                  proofMember(proof).put("attribution", "ALREADY_ABSENT");
                  proofGroup(proof).put("attribution", "ALREADY_ABSENT");
                }));
  }

  @Test
  void readsWellFormedDetachedPrerequisiteProofEvidenceWithoutAttestation() throws IOException {
    final Path report = temp.resolve("valid-detached-proof.json");
    final ObjectMapper mapper = new ObjectMapper();
    mapper.writeValue(report.toFile(), detachedProofPayload(mapper));

    final MavenElisionReportSnapshot replayed = MavenElisionReportWriter.read(report);

    assertAll(
        () -> assertThat(replayed.genericFindings()).hasSize(1),
        () -> assertThat(replayed.genericFindings().getFirst().prerequisiteProof()).isEmpty(),
        () ->
            assertThat(replayed.genericFindings().getFirst().prerequisiteProofEvidence())
                .isPresent());
  }

  @Test
  void rejectsPhysicalPrerequisiteProofEvidenceOnAnAnalysisOnlyOutcome() throws IOException {
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode payload = detachedProofPayload(mapper);
    ((ObjectNode) payload.withArray("genericFindings").get(0))
        .put("outcome", "PLANNED_CODE_ABSENT");
    final Path report = temp.resolve("planned-outcome-with-physical-proof.json");
    mapper.writeValue(report.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("prerequisiteProof");
  }

  @Test
  void applicationProviderTransitionKeepsOnePathIdentity() {
    assertThatThrownBy(
            () ->
                new PrerequisiteProofEvidence.ProviderEvidence(
                    PreconditionClassInventory.ProviderKind.APPLICATION_CLASS_FILE,
                    null,
                    Path.of("/tmp/application-before"),
                    "a".repeat(64),
                    Path.of("/tmp/application-after"),
                    "b".repeat(64),
                    PrerequisiteAbsenceAttribution.PRESENT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("same path");
  }

  private static ArrayNode proofGroups(final ObjectNode proof) {
    return proof.withArray("groups");
  }

  private static ArrayNode proofMembers(final ObjectNode proof) {
    return ((ObjectNode) proofGroups(proof).get(0)).withArray("members");
  }

  private static ObjectNode proofProvider(final ObjectNode proof) {
    return (ObjectNode) proofMember(proof).withArray("providers").get(0);
  }

  private static ObjectNode proofMember(final ObjectNode proof) {
    return (ObjectNode) proofMembers(proof).get(0);
  }

  private static ObjectNode proofGroup(final ObjectNode proof) {
    return (ObjectNode) proofGroups(proof).get(0);
  }

  private void assertMalformedProof(
      final ObjectMapper mapper,
      final ObjectNode validPayload,
      final String name,
      final String expectedField,
      final Consumer<ObjectNode> mutation)
      throws IOException {
    final Path report = temp.resolve(name + ".json");
    final ObjectNode payload = validPayload.deepCopy();
    final ObjectNode proof =
        (ObjectNode) payload.withArray("genericFindings").get(0).get("prerequisiteProof");
    mutation.accept(proof);
    mapper.writeValue(report.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .as("malformed prerequisite proof row: %s", name)
        .isInstanceOf(IOException.class)
        .hasMessageContaining("prerequisiteProof")
        .hasMessageContaining(expectedField);
  }

  private void assertAcceptedProof(
      final ObjectMapper mapper,
      final ObjectNode validPayload,
      final String name,
      final Consumer<ObjectNode> mutation)
      throws IOException {
    final ObjectNode payload = validPayload.deepCopy();
    mutation.accept(
        (ObjectNode) payload.withArray("genericFindings").get(0).get("prerequisiteProof"));
    final Path report = temp.resolve(name + ".json");
    mapper.writeValue(report.toFile(), payload);
    assertThat(
            MavenElisionReportWriter.read(report).genericFindings().getFirst().prerequisiteProof())
        .as("valid detached proof case: %s", name)
        .isEmpty();
  }

  private ObjectNode detachedProofPayload(final ObjectMapper mapper) throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.5");
    final ArtifactCoordinate prerequisite =
        ArtifactCoordinate.of("org.example", "prerequisite", "1.0");
    final Path candidatePath = providerJar("valid-proof-candidate.jar");
    final Path originalPrerequisite =
        providerJar("valid-proof-prerequisite-original.jar", "p/Required");
    final PrerequisiteClaim claim = new PrerequisiteClaim("org.example:prerequisite", "p.Required");
    final PrerequisiteGroup group =
        new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(claim));
    final VulnerabilityFindingContribution contribution =
        new VulnerabilityFindingContribution(
            "CVE-2026-24681",
            Set.of(),
            candidate.groupId(),
            candidate.artifactId(),
            candidate.type(),
            candidate.classifier(),
            List.of(VersionCoverageClaim.affected("[1.5]")),
            FieldValue.omitted(),
            FieldValue.supplied(Set.of(group)),
            MergePriority.MANUAL,
            AssessmentIntent.AUTO_VERIFY,
            "manual:proof-payload",
            Set.of(
                new AdvisoryProvenance(
                    EvidenceOrigin.POM,
                    "proof-payload",
                    URI.create("https://example.test/proof-payload"),
                    null)),
            io.github.spockz.elider.model.ConfidenceLevel.HIGH);
    final GenericVulnerabilityFinding merged =
        GenericVulnerabilityFinding.merge(List.of(contribution));
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.complete(
            List.of(
                provider(candidate, candidatePath), provider(prerequisite, originalPrerequisite)));
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(provider(candidate, candidatePath)));
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(merged, candidate, baseline, actualFinal);
    final GenericFindingAssessment assessment =
        assessmentRow(candidate, contribution, group, proof);
    final Path report = temp.resolve("proof-row-template.json");
    MavenElisionReportWriter.write(report, snapshot(assessment, List.of()));
    return (ObjectNode) mapper.readTree(report.toFile());
  }

  @Test
  void predictionUsesConditionalWordingForRemovedArtifacts() {
    final GenericFindingAssessment original = finding();
    final GenericFindingAssessment removed =
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
            MavenVulnerabilityAssessment.InventoryDisposition.REMOVED,
            original.contributions());
    assertAll(
        () ->
            assertThat(MavenElisionReportGenericRenderer.render(List.of(removed), List.of(), true))
                .anyMatch(line -> line.contains("GHSA-only") && line.contains("[WOULD_REMOVE]")),
        () ->
            assertThat(MavenElisionReportGenericRenderer.render(List.of(removed), List.of(), false))
                .anyMatch(line -> line.contains("GHSA-only") && line.contains("[REMOVED]")));
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
  void partialSourceObservationReplaysAndRejectsIncompleteMetadata() throws IOException {
    final FindingSourceObservation partial =
        new FindingSourceObservation(
            Optional.of(FindingSource.CVE_LIST),
            FindingSourceObservation.Status.valueOf("PARTIAL"),
            "revision-partial",
            Instant.parse("2026-11-04T00:00:00Z"),
            "Skipped malformed source data",
            List.of("CVE-2026-54321 affected[1] skipped"),
            1);
    final MavenElisionReportSnapshot original = snapshot(finding(), List.of(partial));
    final Path output = temp.resolve("partial-report.json");
    MavenElisionReportWriter.write(output, original);
    final MavenElisionReportSnapshot loaded = MavenElisionReportWriter.read(output);
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode root = (ObjectNode) mapper.readTree(output.toFile());
    final ObjectNode noRevision = root.deepCopy();
    ((ObjectNode) noRevision.withArray("sourceObservations").get(0)).putNull("revision");
    final ObjectNode noTime = root.deepCopy();
    ((ObjectNode) noTime.withArray("sourceObservations").get(0)).putNull("lastSuccessfulSync");
    final ObjectNode noDiagnostic = root.deepCopy();
    ((ObjectNode) noDiagnostic.withArray("sourceObservations").get(0)).putNull("diagnostic");
    assertAll(
        () -> assertThat(loaded.sourceObservations()).containsExactly(partial),
        () ->
            assertThat(loaded.genericFindings())
                .usingRecursiveComparison()
                .ignoringCollectionOrder()
                .isEqualTo(original.genericFindings()),
        () ->
            assertThat(String.join("\n", MavenElisionReportWriter.render(loaded)))
                .contains(
                    "PARTIAL",
                    "Skipped malformed source data",
                    "Source diagnostics are in the JSON snapshot")
                .doesNotContain("CVE-2026-54321 affected[1] skipped"),
        () -> assertThat(root.toString()).contains("CVE-2026-54321 affected[1] skipped"),
        () -> assertInvalidPartialReport(mapper, noRevision, "no-revision"),
        () -> assertInvalidPartialReport(mapper, noTime, "no-time"),
        () -> assertInvalidPartialReport(mapper, noDiagnostic, "no-diagnostic"));
  }

  private void assertInvalidPartialReport(
      final ObjectMapper mapper, final ObjectNode payload, final String name) throws IOException {
    final Path path = temp.resolve(name + ".json");
    mapper.writeValue(path.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(path)).isInstanceOf(IOException.class);
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
          assertAll(
              () ->
                  assertThat(replay)
                      .contains("CVE-2026-12345", "DECLARED_CODE_ABSENT", "p.Example", "CVE_LIST")
                      .doesNotContain("https://example.test/source"),
              () ->
                  assertThat(Files.readString(report))
                      .contains("https://example.test/source", "source-label"));
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

  // Each archive entry and ASM writer has independent mutable write state.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path providerJar(final String name, final String... internalNames) throws IOException {
    final Path path = temp.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final String internalName : internalNames) {
        output.putNextEntry(new JarEntry(internalName + ".class"));
        final ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
        writer.visitEnd();
        output.write(writer.toByteArray());
        output.closeEntry();
      }
    }
    return path;
  }

  private static PreconditionClassInventory.Provider provider(
      final ArtifactCoordinate coordinate, final Path path) throws IOException {
    return PreconditionClassInventory.Provider.dependencyArchive(coordinate, path);
  }

  private static GenericFindingAssessment assessmentRow(
      final ArtifactCoordinate candidate,
      final VulnerabilityFindingContribution contribution,
      final PrerequisiteGroup group,
      final PrerequisiteProofResult proof) {
    return assessmentRow(
        candidate,
        contribution.vulnerabilityId(),
        Set.of(contribution.vulnerabilityId()),
        List.of(contribution),
        group,
        proof);
  }

  private static GenericFindingAssessment assessmentRow(
      final ArtifactCoordinate candidate,
      final String vulnerabilityId,
      final Set<String> aliases,
      final List<VulnerabilityFindingContribution> contributions,
      final PrerequisiteGroup group,
      final PrerequisiteProofResult proof) {
    return new GenericFindingAssessment(
        vulnerabilityId,
        aliases,
        candidate,
        VersionApplicability.AFFECTED,
        Optional.of(AssessmentIntent.AUTO_VERIFY),
        ClaimGroupStatus.OMITTED,
        List.of(),
        List.of(),
        ClaimGroupStatus.DECLARED,
        group.members().stream().sorted().toList(),
        List.of(),
        Set.of(),
        Set.of(),
        GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT,
        proof.attestation().impactDetail(),
        MavenVulnerabilityAssessment.InventoryDisposition.RETAINED_AND_TRIMMED,
        contributions,
        Optional.of(proof));
  }

  private static GenericFindingAssessment assessmentRow(
      final ArtifactCoordinate candidate,
      final String vulnerabilityId,
      final GenericFindingAssessment source,
      final PrerequisiteGroup group,
      final PrerequisiteProofResult proof) {
    return assessmentRow(
        candidate, vulnerabilityId, source.aliases(), source.contributions(), group, proof);
  }

  private static VulnerabilityFindingContribution copyContribution(
      final VulnerabilityFindingContribution source,
      final String vulnerabilityId,
      final Set<String> aliases,
      final ArtifactCoordinate component,
      final PrerequisiteGroup group) {
    return new VulnerabilityFindingContribution(
        vulnerabilityId,
        aliases,
        component.groupId(),
        component.artifactId(),
        component.type(),
        component.classifier(),
        source.versionClaims(),
        source.codeGroup(),
        FieldValue.supplied(Set.of(group)),
        source.priority(),
        source.intent(),
        source.provenance(),
        source.sourceProvenance(),
        source.confidenceLevel(),
        source.unresolvedFields());
  }

  private static void assertProofRejected(
      final GenericFindingAssessment finding, final String reason) {
    assertThatThrownBy(() -> MavenElisionReportProofValidator.validate(finding))
        .as(reason)
        .isInstanceOf(IOException.class);
  }

  private static void assertWrongComponentRejected(
      final ArtifactCoordinate candidate,
      final VulnerabilityFindingContribution pom,
      final VulnerabilityFindingContribution osv,
      final ArtifactCoordinate wrongComponent,
      final PrerequisiteGroup group,
      final PrerequisiteProofResult proof) {
    final List<VulnerabilityFindingContribution> contributions =
        List.of(
            pom,
            copyContribution(osv, osv.vulnerabilityId(), osv.aliases(), wrongComponent, group));
    final GenericFindingAssessment finding =
        assessmentRow(
            candidate,
            "CVE-2026-24680",
            Set.of("CVE-2026-24680", "GHSA-25qh-j22f-pwp8", "POM-ALIAS", "OSV-ALIAS"),
            contributions,
            group,
            proof);
    assertProofRejected(finding, "alias-linked advisory on another GATC component");
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
    ((ArrayNode)
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
    final ObjectNode unresolvedGroupProof = original.deepCopy();
    final ObjectNode unresolvedGroupRow =
        (ObjectNode) unresolvedGroupProof.withArray("genericFindings").get(0);
    unresolvedGroupRow.put("outcome", "PREREQUISITES_ABSENT");
    unresolvedGroupRow.put("intent", "AUTO_VERIFY");
    unresolvedGroupRow.put("applicability", "AFFECTED");
    unresolvedGroupRow.put("prerequisiteGroupStatus", "UNRESOLVED");
    final ObjectNode evidenceScopeAsResult = original.deepCopy();
    ((ObjectNode) evidenceScopeAsResult.withArray("genericFindings").get(0))
        .put("applicability", "EVIDENCE_SCOPE");
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
                unresolvedProof,
                unresolvedGroupProof,
                evidenceScopeAsResult)
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

  @Test
  void roundTripsNoAffectedAssertionAsAnAssessmentResult() throws IOException {
    final Path output = temp.resolve("no-affected-assertion.json");
    MavenElisionReportWriter.write(output, snapshot(finding(), List.of()));
    final ObjectMapper mapper = new ObjectMapper();
    final ObjectNode report = (ObjectNode) mapper.readTree(output.toFile());
    final ObjectNode finding = (ObjectNode) report.withArray("genericFindings").get(0);
    finding.put("applicability", "NO_AFFECTED_ASSERTION");
    finding.put("intent", (String) null);
    finding.put("codeGroupStatus", "NOT_APPLICABLE");
    finding.put("prerequisiteGroupStatus", "NOT_APPLICABLE");
    finding.put("outcome", "NO_PROOF");
    finding.put("detail", "No independent affected assertion");
    mapper.writeValue(output.toFile(), report);

    assertThat(MavenElisionReportWriter.read(output).genericFindings())
        .singleElement()
        .satisfies(
            loaded ->
                assertThat(loaded.applicability())
                    .isEqualTo(VersionApplicability.NO_AFFECTED_ASSERTION));
  }

  @Test
  void replaysUnresolvedManualDeclarationsWithoutPromotingThemToProof() throws IOException {
    final GenericFindingAssessment original = finding();
    final VersionCoverageClaim unresolved =
        VersionCoverageClaim.unresolvedRange("[1.4,1.6)", "manual scope uncertain");
    final VulnerabilityFindingContribution contribution =
        original.contributions().getFirst().withVersionClaim(unresolved);
    final GenericFindingAssessment unresolvedManual =
        new GenericFindingAssessment(
            original.vulnerabilityId(),
            original.aliases(),
            original.candidate(),
            VersionApplicability.AFFECTED,
            Optional.of(AssessmentIntent.AUTO_VERIFY),
            ClaimGroupStatus.UNRESOLVED,
            original.codeAttribution(),
            original.heuristicLeads(),
            ClaimGroupStatus.UNRESOLVED,
            original.effectivePrerequisites(),
            List.of(unresolved),
            original.overriddenFields(),
            original.enrichedFields(),
            GenericFindingAssessment.Outcome.UNRESOLVED,
            "Selected manual declarations have unresolved coverage",
            original.inventoryDisposition(),
            List.of(contribution));
    final Path output = temp.resolve("unresolved-manual-declarations.json");
    MavenElisionReportWriter.write(output, snapshot(unresolvedManual, List.of()));
    final GenericFindingAssessment replayed =
        MavenElisionReportWriter.read(output).genericFindings().getFirst();

    assertAll(
        "report replay preserves declarations and the refusal reason without claiming proof",
        () -> assertThat(replayed.codeGroupStatus()).isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () -> assertThat(replayed.prerequisiteGroupStatus()).isEqualTo(ClaimGroupStatus.UNRESOLVED),
        () ->
            assertThat(replayed.effectivePrerequisites())
                .isEqualTo(original.effectivePrerequisites()),
        () -> assertThat(replayed.unresolvedVersionClaims()).containsExactly(unresolved),
        () ->
            assertThat(replayed.outcome()).isEqualTo(GenericFindingAssessment.Outcome.UNRESOLVED));
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
                List.of()),
            null,
            MediatedGraphReportTestSupport.emptyGraph("org.example:consumer:1"),
            MavenElisionPolicyIdentityTestSupport.emptyPolicy());
    final MavenVulnerabilityAssessment.Result result =
        new MavenVulnerabilityAssessment.Result(List.of(), List.of(finding), sources, false);
    return MavenElisionReportSnapshot.from(project, analysis, result);
  }

  private record SerializedProofContext(
      ArtifactCoordinate candidate,
      Path candidateFinalPath,
      PreconditionClassInventory baseline,
      PreconditionClassInventory actualFinal,
      ProviderEvidencePaths providers) {}

  private record ProviderEvidencePaths(
      ArtifactCoordinate presentProvider,
      ArtifactCoordinate droppedProvider,
      ArtifactCoordinate trimmedProvider,
      Path presentBaselinePath,
      Path presentFinalPath,
      Path droppedBaselinePath,
      Path trimmedBaselinePath,
      Path trimmedFinalPath) {}
}
