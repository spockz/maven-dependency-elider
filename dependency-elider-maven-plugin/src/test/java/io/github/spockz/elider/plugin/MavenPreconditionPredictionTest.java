/* WHY: Verifies Analyze's physical prerequisite evidence and planned forecasts. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.advisory.VulnerabilityCacheManager;
import io.github.spockz.elider.applicability.PreconditionClassInventory;
import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.PrerequisiteClaim;
import io.github.spockz.elider.model.PrerequisiteGroup;
import io.github.spockz.elider.model.PrerequisiteOperator;
import io.github.spockz.elider.model.VersionApplicability;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.execution.DefaultMavenExecutionRequest;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Resource;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/* WHY: The scenarios share baseline archives to keep provider inspection fast. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.TooManyMethods",
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AtLeastOneConstructor"
})
final class MavenPreconditionPredictionTest {
  @TempDir Path temporaryDirectory;

  @Test
  void securityFailureCapturingDependencyProviderProducesUnknownForecast() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate provider = ArtifactCoordinate.of("org.example", "prerequisite", "2.0");
    final Artifact providerArtifact =
        artifact(provider, temporaryDirectory.resolve("provider.jar"));
    final AnalyzePrediction template =
        prediction(List.of(providerArtifact), provider, Set.of(), emptyEvidence());
    final Path inaccessiblePath =
        (Path)
            Proxy.newProxyInstance(
                ClassLoader.getPlatformClassLoader(),
                new Class<?>[] {Path.class},
                (proxy, method, arguments) -> {
                  throw new SecurityException("provider read denied");
                });
    final AnalyzePrediction prediction =
        new AnalyzePrediction(
            template.provenance(),
            List.of(
                new ElisionAnalysisModel.ArtifactSnapshot(
                    providerArtifact, provider, inaccessiblePath)),
            template.retainedArtifacts(),
            template.wouldElideArtifacts(),
            template.plannedTrims(),
            template.evidence(),
            template.environmentFingerprint(),
            template.inventoryFingerprint(),
            template.operationFingerprint());

    final MavenProject project = project(temporaryDirectory);
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);
    final PrerequisitePrediction forecast =
        capture.predict(
            candidate,
            Set.of(
                new PrerequisiteGroup(
                    PrerequisiteOperator.ANY_OF,
                    Set.of(new PrerequisiteClaim("org.example:library", "org.example.Required")))));
    final PrerequisitePrediction.MemberForecast member = forecast.groups().get(0).members().get(0);

    assertAll(
        "a denied baseline provider read must keep the Analyze forecast incomplete",
        () -> assertThat(member.state()).isEqualTo(PrerequisitePrediction.MemberState.UNKNOWN),
        () -> assertThat(member.reason()).isEqualTo(PrerequisitePrediction.MemberReason.UNKNOWN),
        () -> assertThat(member.detail()).contains("Could not inspect input artifact"),
        () -> assertThat(forecast.detail()).contains("provider read denied"));
  }

  @Test
  void directAnalyzeScansCurrentRuntimeInputsAndExcludesTestOutput() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate testDependency =
        new ArtifactCoordinate("org.example", "test-support", "1.0", "jar", "", "test");
    final Path candidateArchive = temporaryDirectory.resolve("direct-analyze-library.jar");
    final Path testDependencyArchive =
        temporaryDirectory.resolve("direct-analyze-test-support.jar");
    writeClassJar(candidateArchive, "org/example/Vulnerable");
    writeClassJar(testDependencyArchive, "org/example/Required");
    final Artifact candidateArtifact = artifact(candidate, candidateArchive);
    final Artifact testDependencyArtifact = artifact(testDependency, testDependencyArchive);
    final AnalyzePrediction prediction =
        prediction(
            List.of(candidateArtifact, testDependencyArtifact),
            candidate,
            Set.of(),
            explicitProductionEvidence());
    final MavenProject project = project(temporaryDirectory.resolve("direct-analyze-project"));
    final Path productionClass =
        temporaryDirectory.resolve("direct-analyze-project/target/classes/app/Main.class");
    final Path testOnlyPrerequisite =
        temporaryDirectory.resolve(
            "direct-analyze-project/target/test-classes/org/example/Required.class");
    Files.createDirectories(productionClass.getParent());
    Files.write(productionClass, classBytes("app/Main"));
    Files.createDirectories(testOnlyPrerequisite.getParent());
    Files.write(testOnlyPrerequisite, classBytes("org/example/Required"));
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of("dependency-elider:analyze"));
    final MavenSession session = new MavenSession(null, request, null, project);

    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, session, prediction, true);
    final PrerequisitePrediction forecast =
        capture.predict(candidate, Set.of(anyOf("org.example.Required")));
    final PrerequisitePrediction.MemberForecast member =
        forecast.groups().getFirst().members().getFirst();

    assertAll(
        "direct Analyze observes the current production runtime inventory",
        () -> assertThat(forecast.detail()).isNull(),
        () -> assertThat(member.state()).isEqualTo(PrerequisitePrediction.MemberState.ABSENT),
        () ->
            assertThat(member.reason())
                .isEqualTo(PrerequisitePrediction.MemberReason.ALREADY_ABSENT),
        () -> assertThat(Files.exists(productionClass)).isTrue(),
        () -> assertThat(Files.exists(testOnlyPrerequisite)).isTrue(),
        () -> assertThat(Files.exists(testDependencyArchive)).isTrue());
  }

  @Test
  void directAnalyzeCanProvePrerequisiteAbsenceInItsCurrentRuntimeInventory() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final Path candidateArchive = temporaryDirectory.resolve("direct-proof-library.jar");
    writeClassJar(candidateArchive, "org/example/Vulnerable");
    final AnalyzePrediction prediction =
        prediction(
            List.of(artifact(candidate, candidateArchive)),
            candidate,
            Set.of(),
            explicitProductionEvidence());
    final MavenProject project = project(temporaryDirectory.resolve("direct-proof-project"));
    final Path productionClass =
        temporaryDirectory.resolve("direct-proof-project/target/classes/app/Main.class");
    Files.createDirectories(productionClass.getParent());
    Files.write(productionClass, classBytes("app/Main"));
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of("dependency-elider:analyze"));
    final MavenSession session = new MavenSession(null, request, null, project);
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, session, prediction, true);
    final MavenPreconditionPrediction.Capture unprovenCapture =
        MavenPreconditionPrediction.capture(project, session, prediction);
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-99004");
    mapping.setGroupId(candidate.groupId());
    mapping.setArtifactId(candidate.artifactId());
    mapping.setVersion(candidate.version());
    mapping.setAssertsAffected(true);
    mapping.setRequiresDependency("org.example:required");
    mapping.setRequiresClass("org.example.Required");
    final VulnerabilityCacheManager.CacheConfig cache =
        new VulnerabilityCacheManager.CacheConfig(
            temporaryDirectory.resolve("direct-proof-cache"),
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);

    final ConfiguredVulnerabilityMappings configured =
        ConfiguredVulnerabilityMappings.fromPom(List.of(mapping));
    final MavenVulnerabilityAssessment.Result unprovenAssessment =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(cache, configured, prediction, () -> unprovenCapture);
    final MavenVulnerabilityAssessment.Result assessment =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(cache, configured, prediction, () -> capture);
    final GenericFindingAssessment finding = assessment.genericFindings().getFirst();
    final GenericFindingAssessment unprovenFinding =
        unprovenAssessment.genericFindings().getFirst();
    final Path report = temporaryDirectory.resolve("direct-proof-report.json");
    MavenElisionReportWriter.write(
        report,
        MavenElisionReportSnapshot.from(
            project,
            prediction,
            assessment,
            ExclusionReview.unavailable("Direct Analyze has no captured exclusion provenance")));
    final MavenElisionReportSnapshot replayed = MavenElisionReportWriter.read(report);

    assertAll(
        "current physical absence is proof even when Analyze has no trim to apply",
        () ->
            assertThat(unprovenFinding.outcome())
                .isEqualTo(GenericFindingAssessment.Outcome.NO_PROOF),
        () -> assertThat(unprovenFinding.prerequisitePrediction()).isPresent(),
        () ->
            assertThat(finding.outcome())
                .isEqualTo(GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT),
        () -> assertThat(finding.prerequisiteProof()).isPresent(),
        () -> assertThat(finding.prerequisitePrediction()).isEmpty(),
        () -> assertThat(assessment.attestations()).hasSize(1),
        () -> assertThat(replayed.mode()).isEqualTo(MavenElisionReportSnapshot.Mode.ANALYSIS),
        () ->
            assertThat(replayed.genericFindings())
                .singleElement()
                .satisfies(
                    replayedFinding ->
                        assertAll(
                            () ->
                                assertThat(replayedFinding.outcome())
                                    .isEqualTo(
                                        GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT),
                            () ->
                                assertThat(replayedFinding.prerequisiteProofEvidence())
                                    .isPresent())));
  }

  @Test
  void plannedPrerequisiteRemovalKeepsRetainedAffectedProviderAsPredictionOnly()
      throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate prerequisiteProvider =
        ArtifactCoordinate.of("org.example", "prerequisite", "2.0");
    final Path candidateArchive = temporaryDirectory.resolve("library.jar");
    final Path providerArchive = temporaryDirectory.resolve("prerequisite.jar");
    writeClassJar(candidateArchive, "org/example/Vulnerable");
    writeClassJar(providerArchive, "org/example/Required");
    final Artifact candidateArtifact = artifact(candidate, candidateArchive);
    final Artifact providerArtifact = artifact(prerequisiteProvider, providerArchive);
    final AnalyzePrediction prediction =
        prediction(
            List.of(candidateArtifact, providerArtifact),
            prerequisiteProvider,
            Set.of("org.example.Required"),
            emptyEvidence());
    final MavenProject project = project(temporaryDirectory);
    final MavenSession session = processClassesSession(project);

    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, session, prediction);
    final PrerequisitePrediction forecast =
        capture.predict(
            candidate,
            Set.of(
                new PrerequisiteGroup(
                    PrerequisiteOperator.ANY_OF,
                    Set.of(new PrerequisiteClaim("org.example:library", "org.example.Required")))));
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-99001");
    mapping.setGroupId(candidate.groupId());
    mapping.setArtifactId(candidate.artifactId());
    mapping.setVersion(candidate.version());
    mapping.setAssertsAffected(true);
    mapping.setRequiresDependency("org.example:prerequisite");
    mapping.setRequiresClass("org.example.Required");
    final VulnerabilityCacheManager.CacheConfig cache =
        new VulnerabilityCacheManager.CacheConfig(
            temporaryDirectory.resolve("prediction-cache"),
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);
    final MavenVulnerabilityAssessment.Result assessment =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(
                cache,
                ConfiguredVulnerabilityMappings.fromPom(List.of(mapping)),
                prediction,
                () -> capture);

    assertAll(
        "Analyze records planned absence without asserting physical proof or NOT_AFFECTED",
        () ->
            assertThat(forecast.groups())
                .singleElement()
                .satisfies(
                    group ->
                        assertThat(group.members())
                            .singleElement()
                            .satisfies(
                                member ->
                                    assertAll(
                                        () ->
                                            assertThat(member.state())
                                                .isEqualTo(
                                                    PrerequisitePrediction.MemberState.ABSENT),
                                        () ->
                                            assertThat(member.reason())
                                                .isEqualTo(
                                                    PrerequisitePrediction.MemberReason
                                                        .WOULD_TRIM_CLASS),
                                        () ->
                                            assertThat(member.providers())
                                                .singleElement()
                                                .extracting(
                                                    PrerequisitePrediction.ProviderForecast::plan)
                                                .isEqualTo(
                                                    PrerequisitePrediction.ProviderPlan
                                                        .TRIMMED_CLASS)))),
        () -> assertThat(forecast.candidate()).isEqualTo(candidate),
        () -> assertThat(forecast.planFingerprint()).isEqualTo(prediction.operationFingerprint()),
        () -> assertThat(forecast.baselineInventoryFingerprint()).matches("[0-9a-f]{64}"),
        () -> assertThat(jarContainsClass(providerArchive, "org/example/Required.class")).isTrue(),
        () -> assertThat(assessment.attestations()).isEmpty(),
        () ->
            assertThat(assessment.genericFindings())
                .singleElement()
                .satisfies(
                    finding ->
                        assertAll(
                            () ->
                                assertThat(finding.outcome())
                                    .isEqualTo(
                                        GenericFindingAssessment.Outcome
                                            .PLANNED_PREREQUISITES_ABSENT),
                            () ->
                                assertThat(finding.intent()).contains(AssessmentIntent.AUTO_VERIFY),
                            () ->
                                assertThat(finding.applicability())
                                    .isEqualTo(VersionApplicability.AFFECTED),
                            () ->
                                assertThat(finding.inventoryDisposition())
                                    .isEqualTo(
                                        MavenVulnerabilityAssessment.InventoryDisposition
                                            .RETAINED_UNCHANGED),
                            () -> assertThat(finding.prerequisiteProof()).isEmpty(),
                            () ->
                                assertThat(finding.prerequisitePrediction())
                                    .hasValueSatisfying(
                                        predictionEvidence ->
                                            assertThat(predictionEvidence.groups())
                                                .allSatisfy(
                                                    group ->
                                                        assertThat(group.disarmed()).isTrue())))),
        () -> {
          final ReportReplay reportReplay =
              writeAndReadPredictionReport(
                  project, prediction, assessment, providerArchive, candidateArchive);
          assertAll(
              "detached forecast survives offline replay and remains non-authoritative",
              () ->
                  assertThat(reportReplay.snapshot().mode())
                      .isEqualTo(MavenElisionReportSnapshot.Mode.ANALYSIS),
              () ->
                  assertThat(reportReplay.snapshot().genericFindings())
                      .singleElement()
                      .satisfies(
                          finding ->
                              assertAll(
                                  () -> assertThat(finding.prerequisiteProof()).isEmpty(),
                                  () ->
                                      assertThat(finding.prerequisitePrediction())
                                          .hasValueSatisfying(
                                              predictionEvidence ->
                                                  assertThat(predictionEvidence.groups())
                                                      .allSatisfy(
                                                          group ->
                                                              assertThat(group.disarmed())
                                                                  .isTrue())))),
              () ->
                  assertThat(reportReplay.snapshot().genericFindings())
                      .noneMatch(
                          finding ->
                              finding.outcome()
                                  == GenericFindingAssessment.Outcome.PREREQUISITES_ABSENT),
              () ->
                  rejectsPredictionMutation(
                      reportReplay.reportPath(),
                      "mismatched-plan",
                      "prerequisitePrediction provider plan",
                      finding -> {
                        final com.fasterxml.jackson.databind.node.ObjectNode predictionNode =
                            (com.fasterxml.jackson.databind.node.ObjectNode)
                                finding.get("prerequisitePrediction");
                        final com.fasterxml.jackson.databind.node.ObjectNode group =
                            (com.fasterxml.jackson.databind.node.ObjectNode)
                                predictionNode.withArray("groups").get(0);
                        final com.fasterxml.jackson.databind.node.ObjectNode member =
                            (com.fasterxml.jackson.databind.node.ObjectNode)
                                group.withArray("members").get(0);
                        member.put("reason", "WOULD_ELIDE_DEPENDENCY");
                        ((com.fasterxml.jackson.databind.node.ObjectNode)
                                member.withArray("providers").get(0))
                            .put("plan", "ELIDED");
                      }),
              () ->
                  rejectsPredictionMutation(
                      reportReplay.reportPath(),
                      "undeclared-prerequisite",
                      "effective prerequisites differ from the selected contribution projection",
                      finding -> finding.putArray("effectivePrerequisites")),
              () ->
                  rejectsPredictionMutation(
                      reportReplay.reportPath(),
                      "wrong-prerequisite-status",
                      "requires DECLARED prerequisite groups",
                      finding -> finding.put("prerequisiteGroupStatus", "OMITTED")),
              () ->
                  rejectsPredictionMutation(
                      reportReplay.reportPath(),
                      "unresolved-contribution-with-prediction",
                      "requires DECLARED prerequisite groups",
                      finding -> {
                        finding.put("applicability", "UNRESOLVED");
                        finding.put("prerequisiteGroupStatus", "UNRESOLVED");
                        finding.put("outcome", "UNRESOLVED");
                        finding.put("detail", "Selected contribution scope is unresolved");
                        final com.fasterxml.jackson.databind.node.ObjectNode contribution =
                            (com.fasterxml.jackson.databind.node.ObjectNode)
                                finding.withArray("contributions").get(0);
                        final com.fasterxml.jackson.databind.node.ObjectNode claim =
                            (com.fasterxml.jackson.databind.node.ObjectNode)
                                contribution.withArray("versionClaims").get(0);
                        claim.put("status", "UNRESOLVED");
                        claim.putNull("normalizedMavenRange");
                        claim.put("diagnostic", "Selected contribution scope is unresolved");
                      }),
              () -> rejectsAppliedPrediction(reportReplay.reportPath()));
        });
  }

  @Test
  void completeBytecodeEvidenceCannotTrustEmptyOutputBeforeProcessClasses() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final Path candidateArchive = temporaryDirectory.resolve("initialize-candidate.jar");
    writeClassJar(candidateArchive, "org/example/Vulnerable");
    final ElisionAnalysisModel.AnalysisEvidence evidence =
        new ElisionAnalysisModel.AnalysisEvidence(
            new io.github.spockz.elider.engine.ClassUsageReport(List.of()),
            Optional.empty(),
            Map.of(),
            false,
            false,
            null,
            Set.of());
    final AnalyzePrediction analysisPrediction =
        prediction(List.of(artifact(candidate, candidateArchive)), candidate, Set.of(), evidence);
    final MavenProject project = project(temporaryDirectory.resolve("initialize-project"));
    final Path output = Path.of(project.getBuild().getOutputDirectory());
    try (java.util.stream.Stream<Path> outputEntries = Files.list(output)) {
      assertThat(outputEntries.toList()).isEmpty();
    }

    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(
            project, processClassesSession(project), analysisPrediction);
    Files.createDirectories(output.resolve("org/example"));
    Files.write(output.resolve("org/example/Required.class"), classBytes("org/example/Required"));

    final PrerequisitePrediction forecast =
        capture.predict(candidate, Set.of(anyOf("org.example.Required")));
    final PrerequisitePrediction.MemberForecast member =
        forecast.groups().getFirst().members().getFirst();
    assertAll(
        "Analyze at initialize cannot treat a not-yet-created compiler output root as empty",
        () -> assertThat(member.state()).isEqualTo(PrerequisitePrediction.MemberState.UNKNOWN),
        () -> assertThat(member.detail()).contains("not known complete before the process-classes"),
        () -> assertThat(forecast.groups().getFirst().disarmed()).isFalse());
  }

  @Test
  void retainedAlternateOwnerAndApplicationClassPreventPredictedAbsence() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate trimmedOwner = ArtifactCoordinate.of("org.example", "owner-a", "1");
    final ArtifactCoordinate alternateOwner = ArtifactCoordinate.of("org.example", "owner-b", "1");
    final Path candidateJar = temporaryDirectory.resolve("alternate-candidate.jar");
    final Path trimmedJar = temporaryDirectory.resolve("alternate-trimmed.jar");
    final Path alternateJar = temporaryDirectory.resolve("alternate-kept.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(trimmedJar, "org/example/Required");
    writeClassJar(alternateJar, "org/example/Required");
    final AnalyzePrediction prediction =
        prediction(
            List.of(
                artifact(candidate, candidateJar),
                artifact(trimmedOwner, trimmedJar),
                artifact(alternateOwner, alternateJar)),
            trimmedOwner,
            Set.of("org.example.Required"),
            emptyEvidence());
    final MavenProject project = project(temporaryDirectory.resolve("alternate-project"));
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);
    final PrerequisiteGroup group = anyOf("org.example.Required");

    final PrerequisitePrediction forecast = capture.predict(candidate, Set.of(group));

    assertThat(forecast.groups())
        .singleElement()
        .satisfies(
            value ->
                assertThat(value.members())
                    .singleElement()
                    .extracting(PrerequisitePrediction.MemberForecast::state)
                    .isEqualTo(PrerequisitePrediction.MemberState.PRESENT));
    assertThat(forecast.groups().getFirst().members().getFirst().providers())
        .anySatisfy(provider -> assertThat(provider.coordinate()).isEqualTo(alternateOwner));
  }

  @Test
  void plannedCodeAbsenceKeepsPrecedenceOverPrerequisiteForecast() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate owner = ArtifactCoordinate.of("org.example", "owner", "1");
    final Path candidateArchive = temporaryDirectory.resolve("planned-code-candidate.jar");
    final Path ownerArchive = temporaryDirectory.resolve("planned-code-owner.jar");
    writeClassJar(candidateArchive, "org/example/Vulnerable");
    writeClassJar(ownerArchive, "org/example/Required");
    final AnalyzePrediction prediction =
        prediction(
            List.of(artifact(candidate, candidateArchive), artifact(owner, ownerArchive)),
            List.of(candidate, owner),
            List.of(),
            List.of(
                new AnalyzePrediction.PlannedTrim(candidate, Set.of("org.example.Vulnerable")),
                new AnalyzePrediction.PlannedTrim(owner, Set.of("org.example.Required"))),
            emptyEvidence());
    final MavenProject project = project(temporaryDirectory.resolve("planned-code-project"));
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);
    final VulnerabilityMappingConfig mapping = new VulnerabilityMappingConfig();
    mapping.setCveId("CVE-2026-99003");
    mapping.setGroupId(candidate.groupId());
    mapping.setArtifactId(candidate.artifactId());
    mapping.setVersion(candidate.version());
    mapping.setAssertsAffected(true);
    mapping.setVulnerableClasses(List.of("org.example.Vulnerable"));
    mapping.setRequiresDependency("org.example:owner");
    mapping.setRequiresClass("org.example.Required");
    final VulnerabilityCacheManager.CacheConfig cache =
        new VulnerabilityCacheManager.CacheConfig(
            temporaryDirectory.resolve("planned-code-cache"),
            null,
            null,
            Duration.ofHours(24),
            false,
            true,
            VulnerabilityCacheManager.bundledEmptySeed(),
            MavenAssessmentFixtures.CACHE_PRODUCER);
    final MavenVulnerabilityAssessment.Result assessment =
        new MavenVulnerabilityAssessment(new RecordingMavenLog())
            .assess(
                cache,
                ConfiguredVulnerabilityMappings.fromPom(List.of(mapping)),
                prediction,
                () -> capture);

    assertAll(
        "planned code outcome remains primary when prerequisites are also predicted absent",
        () -> assertThat(assessment.attestations()).isEmpty(),
        () ->
            assertThat(assessment.genericFindings())
                .singleElement()
                .satisfies(
                    finding ->
                        assertAll(
                            () ->
                                assertThat(finding.outcome())
                                    .isEqualTo(
                                        GenericFindingAssessment.Outcome.PLANNED_CODE_ABSENT),
                            () -> assertThat(finding.prerequisitePrediction()).isPresent())));
  }

  @Test
  void identicalPhysicalMembersUseAnyOfAndAllOfOperatorsIndependently() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate owner = ArtifactCoordinate.of("org.example", "owner", "1");
    final Path candidateJar = temporaryDirectory.resolve("operators-candidate.jar");
    final Path ownerJar = temporaryDirectory.resolve("operators-owner.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(ownerJar, "org/example/Present");
    final AnalyzePrediction prediction =
        prediction(
            List.of(artifact(candidate, candidateJar), artifact(owner, ownerJar)),
            owner,
            Set.of(),
            emptyEvidence());
    final Path basedir = temporaryDirectory.resolve("operators-project");
    final MavenProject project = project(basedir);
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);
    final PrerequisiteClaim present =
        new PrerequisiteClaim("org.example:owner", "org.example.Present");
    final PrerequisiteClaim absent =
        new PrerequisiteClaim("org.example:owner", "org.example.Absent");

    final PrerequisitePrediction.GroupForecast anyOf =
        capture
            .predict(
                candidate,
                Set.of(new PrerequisiteGroup(PrerequisiteOperator.ANY_OF, Set.of(present, absent))))
            .groups()
            .getFirst();
    final PrerequisitePrediction.GroupForecast allOf =
        capture
            .predict(
                candidate,
                Set.of(new PrerequisiteGroup(PrerequisiteOperator.ALL_OF, Set.of(present, absent))))
            .groups()
            .getFirst();

    assertAll(
        "both operators share the same inspected physical member states",
        () ->
            assertThat(anyOf.members())
                .extracting(PrerequisitePrediction.MemberForecast::state)
                .containsExactlyInAnyOrder(
                    PrerequisitePrediction.MemberState.PRESENT,
                    PrerequisitePrediction.MemberState.ABSENT),
        () ->
            assertThat(allOf.members())
                .extracting(PrerequisitePrediction.MemberForecast::state)
                .containsExactlyInAnyOrder(
                    PrerequisitePrediction.MemberState.PRESENT,
                    PrerequisitePrediction.MemberState.ABSENT),
        () -> assertThat(anyOf.disarmed()).isFalse(),
        () -> assertThat(allOf.disarmed()).isTrue());
  }

  @Test
  void exactClassInApplicationRootSurvivesPlannedDependencyRemoval() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate owner = ArtifactCoordinate.of("org.example", "owner", "1");
    final Path candidateJar = temporaryDirectory.resolve("application-candidate.jar");
    final Path ownerJar = temporaryDirectory.resolve("application-owner.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(ownerJar, "org/example/Required");
    final Path basedir = temporaryDirectory.resolve("application-project");
    final MavenProject project = project(basedir);
    final Path applicationClass = basedir.resolve("target/classes/org/example/Required.class");
    Files.createDirectories(applicationClass.getParent());
    Files.write(applicationClass, classBytes("org/example/Required"));
    final AnalyzePrediction prediction =
        prediction(
            List.of(artifact(candidate, candidateJar), artifact(owner, ownerJar)),
            owner,
            Set.of("org.example.Required"),
            emptyEvidence());
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);

    final PrerequisitePrediction forecast =
        capture.predict(candidate, Set.of(anyOf("org.example.Required")));

    assertThat(forecast.groups().getFirst().members().getFirst().state())
        .isEqualTo(PrerequisitePrediction.MemberState.PRESENT);
    assertThat(forecast.groups().getFirst().members().getFirst().providers())
        .anySatisfy(
            provider ->
                assertThat(provider.kind())
                    .isEqualTo(PreconditionClassInventory.ProviderKind.APPLICATION_CLASS_FILE));
  }

  @Test
  void applicationResourceAndAllDroppedDuplicateOwnersAreProjectedCorrectly() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate ownerA = ArtifactCoordinate.of("org.example", "owner-a", "1");
    final ArtifactCoordinate ownerB = ArtifactCoordinate.of("org.example", "owner-b", "1");
    final Path candidateJar = temporaryDirectory.resolve("duplicate-candidate.jar");
    final Path ownerAlphaJar = temporaryDirectory.resolve("duplicate-owner-a.jar");
    final Path ownerBetaJar = temporaryDirectory.resolve("duplicate-owner-b.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(ownerAlphaJar, "org/example/Required");
    writeClassJar(ownerBetaJar, "org/example/Required");
    final List<Artifact> artifacts =
        List.of(
            artifact(candidate, candidateJar),
            artifact(ownerA, ownerAlphaJar),
            artifact(ownerB, ownerBetaJar));
    final Path basedir = temporaryDirectory.resolve("resource-duplicate-project");
    final MavenProject project = project(basedir);
    final Path resourceClass = basedir.resolve("src/main/resources/org/example/Required.bin");
    Files.createDirectories(resourceClass.getParent());
    Files.write(resourceClass, classBytes("org/example/Required"));
    final AnalyzePrediction prediction =
        prediction(
            artifacts, List.of(candidate), List.of(ownerA, ownerB), List.of(), emptyEvidence());
    final MavenPreconditionPrediction.Capture capture =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), prediction);

    final PrerequisitePrediction resourceForecast =
        capture.predict(candidate, Set.of(anyOf("org.example.Required")));
    final MavenProject droppedProject = project(temporaryDirectory.resolve("all-dropped-project"));
    final PrerequisitePrediction droppedForecast =
        MavenPreconditionPrediction.capture(
                droppedProject, processClassesSession(droppedProject), prediction)
            .predict(candidate, Set.of(anyOf("org.example.Required")));
    final AnalyzePrediction mixedPlan =
        prediction(
            artifacts,
            List.of(candidate, ownerB),
            List.of(ownerA),
            List.of(new AnalyzePrediction.PlannedTrim(ownerB, Set.of("org.example.Required"))),
            emptyEvidence());
    final PrerequisitePrediction mixedForecast =
        MavenPreconditionPrediction.capture(
                droppedProject, processClassesSession(droppedProject), mixedPlan)
            .predict(candidate, Set.of(anyOf("org.example.Required")));

    assertAll(
        "application resources survive while all duplicate dropped dependency owners disappear",
        () ->
            assertThat(resourceForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.PRESENT),
        () ->
            assertThat(resourceForecast.groups().getFirst().members().getFirst().providers())
                .anySatisfy(
                    provider ->
                        assertThat(provider.kind())
                            .isEqualTo(
                                PreconditionClassInventory.ProviderKind.APPLICATION_RESOURCE_FILE)),
        () ->
            assertThat(droppedForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.ABSENT),
        () ->
            assertThat(droppedForecast.groups().getFirst().members().getFirst().providers())
                .extracting(PrerequisitePrediction.ProviderForecast::plan)
                .containsOnly(PrerequisitePrediction.ProviderPlan.ELIDED),
        () ->
            assertThat(mixedForecast.groups().getFirst().members().getFirst().reason())
                .isEqualTo(PrerequisitePrediction.MemberReason.MIXED),
        () ->
            assertThat(mixedForecast.groups().getFirst().members().getFirst().providers())
                .extracting(PrerequisitePrediction.ProviderForecast::plan)
                .containsExactlyInAnyOrder(
                    PrerequisitePrediction.ProviderPlan.ELIDED,
                    PrerequisitePrediction.ProviderPlan.TRIMMED_CLASS));
  }

  @Test
  void trimOffRetainsOriginalClassAndUpperMrjarTierRemainsPresent() throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate owner = ArtifactCoordinate.of("org.example", "owner", "1");
    final Path candidateJar = temporaryDirectory.resolve("trim-off-candidate.jar");
    final Path ownerJar = temporaryDirectory.resolve("trim-off-owner.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(ownerJar, "org/example/Required");
    final AnalyzePrediction trimOff =
        prediction(
            List.of(artifact(candidate, candidateJar), artifact(owner, ownerJar)),
            List.of(candidate, owner),
            List.of(),
            List.of(),
            emptyEvidence());
    final Path mrjar = temporaryDirectory.resolve("upper-tier-owner.jar");
    writeMultiReleaseClassJar(mrjar, "org/example/UpperOnly", 17);
    final ArtifactCoordinate mrOwner = ArtifactCoordinate.of("org.example", "mr-owner", "1");
    final AnalyzePrediction upperTier =
        prediction(
            List.of(artifact(candidate, candidateJar), artifact(mrOwner, mrjar)),
            mrOwner,
            Set.of("org.example.BaseRemoved"),
            emptyEvidence());
    final MavenProject project = project(temporaryDirectory.resolve("trim-off-project"));
    final PrerequisitePrediction trimOffForecast =
        MavenPreconditionPrediction.capture(project, processClassesSession(project), trimOff)
            .predict(candidate, Set.of(anyOf("org.example.Required")));
    final MavenProject mrProject = project(temporaryDirectory.resolve("upper-tier-project"));
    final PrerequisitePrediction upperForecast =
        MavenPreconditionPrediction.capture(mrProject, processClassesSession(mrProject), upperTier)
            .predict(candidate, Set.of(anyOf("org.example.UpperOnly")));

    assertAll(
        "untouched archives and upper MRJAR implementations remain available",
        () ->
            assertThat(trimOffForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.PRESENT),
        () ->
            assertThat(upperTier.plannedTrims().getFirst().removedClasses())
                .doesNotContain("org.example.UpperOnly"),
        () ->
            assertThat(upperForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.PRESENT),
        () -> assertThat(jarContainsClass(ownerJar, "org/example/Required.class")).isTrue());
  }

  @Test
  void completeBaselineWithoutClassIsAlreadyAbsentAndIncompleteRootsStayUnknown()
      throws IOException {
    final ArtifactCoordinate candidate = ArtifactCoordinate.of("org.example", "library", "1.0");
    final ArtifactCoordinate knownOwner = ArtifactCoordinate.of("org.example", "owner", "1");
    final Path candidateJar = temporaryDirectory.resolve("already-absent.jar");
    final Path knownOwnerJar = temporaryDirectory.resolve("known-present.jar");
    writeClassJar(candidateJar, "org/example/Vulnerable");
    writeClassJar(knownOwnerJar, "org/example/Present");
    final AnalyzePrediction prediction =
        prediction(
            List.of(artifact(candidate, candidateJar), artifact(knownOwner, knownOwnerJar)),
            List.of(candidate, knownOwner),
            List.of(),
            List.of(),
            emptyEvidence());
    final Path completeBasedir = temporaryDirectory.resolve("already-absent-project");
    final MavenProject completeProject = project(completeBasedir);
    final PrerequisitePrediction completeForecast =
        MavenPreconditionPrediction.capture(
                completeProject, processClassesSession(completeProject), prediction)
            .predict(candidate, Set.of(anyOf("org.example.Missing")));

    final Path incompleteBasedir = temporaryDirectory.resolve("incomplete-project");
    final MavenProject incompleteProject = project(incompleteBasedir);
    Files.delete(incompleteBasedir.resolve("target/classes"));
    Files.writeString(incompleteBasedir.resolve("target/classes"), "not a directory");
    final PrerequisitePrediction incompleteForecast =
        MavenPreconditionPrediction.capture(
                incompleteProject, processClassesSession(incompleteProject), prediction)
            .predict(candidate, Set.of(anyOf("org.example.Missing")));
    final PrerequisitePrediction incompleteKnownPositive =
        MavenPreconditionPrediction.capture(
                incompleteProject, processClassesSession(incompleteProject), prediction)
            .predict(candidate, Set.of(anyOf("org.example.Present")));

    assertAll(
        "known absence requires a complete baseline provider inventory",
        () ->
            assertThat(completeForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.ABSENT),
        () -> assertThat(completeForecast.detail()).isNull(),
        () ->
            assertThat(incompleteForecast.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.UNKNOWN),
        () -> assertThat(incompleteForecast.detail()).contains("provider root"),
        () ->
            assertThat(incompleteKnownPositive.groups().getFirst().members().getFirst().state())
                .isEqualTo(PrerequisitePrediction.MemberState.PRESENT),
        () -> assertThat(incompleteKnownPositive.detail()).contains("provider root"));
  }

  private static Artifact artifact(final ArtifactCoordinate coordinate, final Path file) {
    final Artifact artifact =
        new DefaultArtifact(
            coordinate.groupId(),
            coordinate.artifactId(),
            coordinate.version(),
            coordinate.scope(),
            coordinate.type(),
            coordinate.classifier(),
            new DefaultArtifactHandler(coordinate.type()));
    artifact.setFile(file.toFile());
    return artifact;
  }

  private static AnalyzePrediction prediction(
      final List<Artifact> artifacts,
      final ArtifactCoordinate plannedTrim,
      final Set<String> removedClasses,
      final ElisionAnalysisModel.AnalysisEvidence evidence) {
    return prediction(
        artifacts,
        artifacts.stream().map(MavenArtifactInventory::toCoordinate).toList(),
        List.of(),
        removedClasses.isEmpty()
            ? List.of()
            : List.of(new AnalyzePrediction.PlannedTrim(plannedTrim, removedClasses)),
        evidence);
  }

  private static AnalyzePrediction prediction(
      final List<Artifact> artifacts,
      final List<ArtifactCoordinate> retained,
      final List<ArtifactCoordinate> elided,
      final List<AnalyzePrediction.PlannedTrim> trims,
      final ElisionAnalysisModel.AnalysisEvidence evidence) {
    return new AnalyzePrediction(
        MavenAnalysisResolutionContext.Provenance.DETACHED_CURRENT_MODEL,
        artifacts.stream().map(ElisionAnalysisModel.ArtifactSnapshot::from).toList(),
        retained,
        elided,
        trims,
        evidence,
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(64));
  }

  private static MavenProject project(final Path basedir) throws IOException {
    final MavenProject project = new MavenProject();
    project.setFile(basedir.resolve("pom.xml").toFile());
    project.setPackaging("jar");
    final Build build = new Build();
    build.setDirectory(basedir.resolve("target").toString());
    build.setOutputDirectory(basedir.resolve("target/classes").toString());
    build.setTestOutputDirectory(basedir.resolve("target/test-classes").toString());
    project.setBuild(build);
    final Resource resource = new Resource();
    resource.setDirectory(basedir.resolve("src/main/resources").toString());
    project.addResource(resource);
    final Resource testResource = new Resource();
    testResource.setDirectory(basedir.resolve("src/test/resources").toString());
    project.addTestResource(testResource);
    Files.createDirectories(basedir.resolve("target/classes"));
    Files.createDirectories(basedir.resolve("target/test-classes"));
    Files.createDirectories(basedir.resolve("src/main/resources"));
    Files.createDirectories(basedir.resolve("src/test/resources"));
    return project;
  }

  private static MavenSession processClassesSession(final MavenProject project) {
    final DefaultMavenExecutionRequest request = new DefaultMavenExecutionRequest();
    request.setGoals(List.of("clean", "process-classes"));
    return new MavenSession(null, request, null, project);
  }

  private static byte[] classBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static ElisionAnalysisModel.AnalysisEvidence emptyEvidence() {
    return new ElisionAnalysisModel.AnalysisEvidence(
        new io.github.spockz.elider.engine.ClassUsageReport(List.of()),
        Optional.empty(),
        Map.of(),
        false,
        true,
        null,
        Set.of());
  }

  private static ElisionAnalysisModel.AnalysisEvidence explicitProductionEvidence() {
    return new ElisionAnalysisModel.AnalysisEvidence(
        new io.github.spockz.elider.engine.ClassUsageReport(List.of()),
        Optional.empty(),
        Map.of(),
        true,
        false,
        null,
        Set.of());
  }

  private static PrerequisiteGroup anyOf(final String className) {
    return new PrerequisiteGroup(
        PrerequisiteOperator.ANY_OF,
        Set.of(new PrerequisiteClaim("org.example:required", className)));
  }

  private static void writeClassJar(final Path archive, final String internalName)
      throws IOException {
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      output.putNextEntry(new JarEntry(internalName + ".class"));
      output.write(classBytes(internalName));
      output.closeEntry();
    }
  }

  private static void writeMultiReleaseClassJar(
      final Path archive, final String internalName, final int release) throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive), manifest)) {
      output.putNextEntry(
          new JarEntry("META-INF/versions/" + release + "/" + internalName + ".class"));
      output.write(classBytes(internalName));
      output.closeEntry();
    }
  }

  private static boolean jarContainsClass(final Path archive, final String entry)
      throws IOException {
    try (java.util.jar.JarFile jar = new java.util.jar.JarFile(archive.toFile())) {
      return jar.getEntry(entry) != null;
    }
  }

  private ReportReplay writeAndReadPredictionReport(
      final MavenProject project,
      final AnalyzePrediction prediction,
      final MavenVulnerabilityAssessment.Result assessment,
      final Path providerArchive,
      final Path candidateArchive)
      throws IOException {
    final Path report = temporaryDirectory.resolve("prediction-report.json");
    final MavenElisionReportSnapshot snapshot =
        MavenElisionReportSnapshot.from(
            project,
            prediction,
            assessment,
            ExclusionReview.unavailable("Analysis prediction has no physical proof"));
    MavenElisionReportWriter.write(report, snapshot);
    Files.delete(providerArchive);
    Files.delete(candidateArchive);
    return new ReportReplay(MavenElisionReportWriter.read(report), report);
  }

  private static void rejectsAppliedPrediction(final Path report) throws IOException {
    final com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    final com.fasterxml.jackson.databind.node.ObjectNode payload =
        (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(report.toFile());
    payload.put("mode", MavenElisionReportSnapshot.Mode.APPLIED.name());
    payload.put("uncompressedProgramClassBytesPruned", 0L);
    for (final com.fasterxml.jackson.databind.JsonNode row :
        payload.withArray("trimmedArtifacts")) {
      final com.fasterxml.jackson.databind.node.ObjectNode trim =
          (com.fasterxml.jackson.databind.node.ObjectNode) row;
      trim.put("uncompressedProgramClassBytesPruned", 0L);
      trim.putNull("plannedClasses");
    }
    mapper.writeValue(report.toFile(), payload);
    assertThatThrownBy(() -> MavenElisionReportWriter.read(report))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Applied report cannot contain prerequisite prediction");
  }

  private void rejectsPredictionMutation(
      final Path sourceReport,
      final String name,
      final String expectedMessage,
      final java.util.function.Consumer<com.fasterxml.jackson.databind.node.ObjectNode> mutation)
      throws IOException {
    final com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper();
    final com.fasterxml.jackson.databind.node.ObjectNode payload =
        (com.fasterxml.jackson.databind.node.ObjectNode) mapper.readTree(sourceReport.toFile());
    mutation.accept(
        (com.fasterxml.jackson.databind.node.ObjectNode)
            payload.withArray("genericFindings").get(0));
    final Path mutatedReport = temporaryDirectory.resolve(name + ".json");
    mapper.writeValue(mutatedReport.toFile(), payload);

    assertThatThrownBy(() -> MavenElisionReportWriter.read(mutatedReport))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(expectedMessage);
  }

  private record ReportReplay(MavenElisionReportSnapshot snapshot, Path reportPath) {}
}
