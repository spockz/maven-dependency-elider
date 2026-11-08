/* WHY: Verifies prerequisite proof causes from exact baseline and final class providers. */

package io.github.spockz.elider.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.groups.Tuple.tuple;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.PreconditionClassInventory.Provider;
import io.github.spockz.elider.model.PreconditionProof.InventoryPair;
import io.github.spockz.elider.model.PrerequisiteProofResult.ProviderOutcome;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks physical prerequisite attribution. */
final class PrerequisiteAttributionTest {
  /** Temporary archives for each isolated baseline and staged inventory. */
  @TempDir private Path directory;

  @SuppressWarnings({"PMD.UnnecessaryConstructor", "PMD.UncommentedEmptyConstructor"})
  /* package */ PrerequisiteAttributionTest() {}

  @Test
  void completeInventoriesDistinguishAlreadyAbsentFromElidedAndTrimmedProviders()
      throws IOException {
    assertAll(
        "absence attribution follows observed provider changes",
        () -> {
          final Provider candidate =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.CANDIDATE,
                  "absent-candidate.jar",
                  Map.of());
          final PrerequisiteProofResult result =
              PrerequisiteAttributionFixtures.prove(
                  PreconditionClassInventory.complete(List.of(candidate)),
                  PreconditionClassInventory.complete(List.of(candidate)));
          assertAll(
              () -> assertThat(result.attestation()).isNotNull(),
              () ->
                  assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                      .isEqualTo(PrerequisiteAbsenceAttribution.ALREADY_ABSENT),
              () ->
                  assertThat(
                          PrerequisiteAttributionFixtures.onlyGroup(result)
                              .members()
                              .getFirst()
                              .providers())
                      .isEmpty());
        },
        () -> {
          final Provider candidate =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.CANDIDATE,
                  "elided-candidate.jar",
                  Map.of());
          final Provider original =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.PROVIDER_ONE,
                  "provider-original.jar",
                  PrerequisiteAttributionFixtures.requiredClass());
          final PrerequisiteProofResult result =
              PrerequisiteAttributionFixtures.prove(
                  PreconditionClassInventory.complete(List.of(candidate, original)),
                  PreconditionClassInventory.complete(List.of(candidate)));
          assertAll(
              () ->
                  assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                      .isEqualTo(PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY),
              () ->
                  assertThat(
                          PrerequisiteAttributionFixtures.onlyGroup(result)
                              .members()
                              .getFirst()
                              .providers())
                      .extracting(ProviderOutcome::attribution)
                      .containsExactly(PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY));
        },
        () -> {
          final Provider candidate =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.CANDIDATE,
                  "trimmed-candidate.jar",
                  Map.of());
          final Provider original =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.PROVIDER_ONE,
                  "provider-trimmed-original.jar",
                  PrerequisiteAttributionFixtures.requiredClass());
          final Provider staged =
              PrerequisiteAttributionFixtures.archive(
                  directory,
                  PrerequisiteAttributionFixtures.PROVIDER_ONE,
                  "provider-trimmed-final.jar",
                  Map.of());
          final PrerequisiteProofResult result =
              PrerequisiteAttributionFixtures.prove(
                  PreconditionClassInventory.complete(List.of(candidate, original)),
                  PreconditionClassInventory.complete(List.of(candidate, staged)));
          final ProviderOutcome provider =
              PrerequisiteAttributionFixtures.onlyGroup(result)
                  .members()
                  .getFirst()
                  .providers()
                  .getFirst();
          assertAll(
              () ->
                  assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                      .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS),
              () ->
                  assertThat(provider.attribution())
                      .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS),
              () -> assertThat(provider.baselinePath()).isEqualTo(original.path()),
              () -> assertThat(provider.finalPath()).isEqualTo(staged.path()),
              () -> assertThat(provider.coordinate()).isEqualTo(original.coordinate()));
        });
  }

  @Test
  void baselineSecurityFailureKeepsFinalProofAndMarksCauseUnknown() throws IOException {
    final Provider baselineCandidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "security-baseline-candidate.jar",
            Map.of());
    final Provider finalCandidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "security-final-candidate.jar",
            Map.of());
    final Provider baselineProvider =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_ONE,
            "security-baseline-provider.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.complete(List.of(baselineCandidate, baselineProvider));
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(finalCandidate));
    final InventoryPair pair =
        PreconditionProof.inspectPair(
            baseline,
            actualFinal,
            inventory -> {
              if (inventory == baseline) {
                throw new SecurityException("baseline access denied");
              }
              return PreconditionProof.inspect(inventory);
            });
    final PrerequisiteProofResult proof =
        PreconditionProof.proveWithAttribution(
            PrerequisiteAttributionFixtures.finding("CVE-2025-12346"),
            PrerequisiteAttributionFixtures.CANDIDATE,
            pair);

    assertAll(
        "baseline access failure does not invalidate actual-final absence proof",
        () -> assertThat(proof.attestation()).isNotNull(),
        () -> assertThat(pair.baselineDetail()).contains("baseline access denied"),
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(proof).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN));
  }

  @Test
  void finalSecurityFailureRefusesTheInventoryPair() throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "security-final-refusal-candidate.jar",
            Map.of());
    final PreconditionClassInventory inventory =
        PreconditionClassInventory.complete(List.of(candidate));

    assertThatThrownBy(
            () ->
                PreconditionProof.inspectPair(
                    inventory,
                    inventory,
                    ignored -> {
                      throw new SecurityException("final access denied");
                    }))
        .isInstanceOf(SecurityException.class)
        .hasMessageContaining("final access denied");
  }

  @Test
  void duplicateProvidersThatDisappearByDifferentRoutesAreMixed() throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory, PrerequisiteAttributionFixtures.CANDIDATE, "mixed-candidate.jar", Map.of());
    final Provider originalOne =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_ONE,
            "mixed-one.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final Provider originalTwo =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_TWO,
            "mixed-two.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final Provider stagedTwo =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_TWO,
            "mixed-two-trimmed.jar",
            Map.of());

    final PrerequisiteProofResult result =
        PrerequisiteAttributionFixtures.prove(
            PreconditionClassInventory.complete(List.of(candidate, originalOne, originalTwo)),
            PreconditionClassInventory.complete(List.of(candidate, stagedTwo)));

    assertAll(
        "duplicate providers retain their individual removal causes",
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.MIXED),
        () ->
            assertThat(
                    PrerequisiteAttributionFixtures.onlyGroup(result)
                        .members()
                        .getFirst()
                        .providers())
                .extracting(
                    ProviderOutcome::coordinate,
                    ProviderOutcome::baselinePath,
                    ProviderOutcome::finalPath,
                    ProviderOutcome::attribution)
                .containsExactlyInAnyOrder(
                    tuple(
                        PrerequisiteAttributionFixtures.PROVIDER_ONE,
                        originalOne.path(),
                        null,
                        PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY),
                    tuple(
                        PrerequisiteAttributionFixtures.PROVIDER_TWO,
                        originalTwo.path(),
                        stagedTwo.path(),
                        PrerequisiteAbsenceAttribution.TRIMMED_CLASS)));
  }

  @Test
  void sameGroupArtifactWithDifferentVersionTypeAndClassifierIsNotTheSameProvider()
      throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "identity-candidate.jar",
            Map.of());
    final Provider original =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_ONE,
            "identity-original.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final ArtifactCoordinate relatedCoordinate =
        new ArtifactCoordinate(
            PrerequisiteAttributionFixtures.PROVIDER_ONE.groupId(),
            PrerequisiteAttributionFixtures.PROVIDER_ONE.artifactId(),
            "2.0",
            "test-jar",
            "tests",
            "runtime");
    final Provider relatedFinal =
        PrerequisiteAttributionFixtures.archive(
            directory, relatedCoordinate, "identity-related.jar", Map.of());

    final PrerequisiteProofResult result =
        PrerequisiteAttributionFixtures.prove(
            PreconditionClassInventory.complete(List.of(candidate, original)),
            PreconditionClassInventory.complete(List.of(candidate, relatedFinal)));

    assertAll(
        "provider comparison uses full Maven artifact identity, not group and artifact alone",
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY),
        () ->
            assertThat(
                    PrerequisiteAttributionFixtures.onlyGroup(result)
                        .members()
                        .getFirst()
                        .providers())
                .containsExactly(
                    new ProviderOutcome(
                        PreconditionClassInventory.ProviderKind.DEPENDENCY_ARCHIVE,
                        PrerequisiteAttributionFixtures.PROVIDER_ONE,
                        original.path(),
                        null,
                        PrerequisiteAbsenceAttribution.ELIDED_DEPENDENCY)));
  }

  @Test
  void incompleteBaselineAllowsCompleteFinalAbsenceProofWithUnknownAttribution()
      throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "unknown-candidate.jar",
            Map.of());
    final Provider knownProvider =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_ONE,
            "unknown-known-provider.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.incomplete(
            List.of(candidate, knownProvider), "missing app output");
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(candidate));

    final PrerequisiteProofResult result =
        PrerequisiteAttributionFixtures.prove(baseline, actualFinal);

    assertAll(
        "incomplete baseline affects attribution, not complete final absence proof",
        () -> assertThat(result.attestation()).isNotNull(),
        () ->
            assertThat(result.attestation().inventorySha256()).isEqualTo(actualFinal.fingerprint()),
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN),
        () -> assertThat(result.baselineDetail()).isEqualTo("missing app output"));
  }

  @Test
  void changedApplicationProviderHasUnknownAttribution() throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.CANDIDATE,
            "application-candidate.jar",
            Map.of());
    final Path applicationClassPath = directory.resolve("application/Required.class");
    Files.createDirectories(applicationClassPath.getParent());
    Files.write(
        applicationClassPath,
        PrerequisiteAttributionFixtures.requiredClass().get("org/example/Required.class"));
    final Provider applicationProvider = Provider.applicationClassFile(applicationClassPath);
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.complete(List.of(candidate, applicationProvider));
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(candidate));

    final PrerequisiteProofResult result =
        PrerequisiteAttributionFixtures.prove(baseline, actualFinal);

    assertAll(
        "application class changes are not attributed to dependency elision or trimming",
        () -> assertThat(result.attestation()).isNotNull(),
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(result).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.UNKNOWN),
        () ->
            assertThat(
                    PrerequisiteAttributionFixtures.onlyGroup(result)
                        .members()
                        .getFirst()
                        .providers())
                .extracting(ProviderOutcome::attribution)
                .containsExactly(PrerequisiteAbsenceAttribution.UNKNOWN));
  }

  @Test
  void incompleteFinalInventoryCannotProduceAnAttestation() throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory, PrerequisiteAttributionFixtures.CANDIDATE, "final-candidate.jar", Map.of());
    final PreconditionClassInventory completeBaseline =
        PreconditionClassInventory.complete(List.of(candidate));
    final PreconditionClassInventory incompleteFinal =
        PreconditionClassInventory.incomplete(List.of(candidate), "staged archive unreadable");

    assertThatThrownBy(
            () -> PrerequisiteAttributionFixtures.prove(completeBaseline, incompleteFinal))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Precondition inventory is incomplete: staged archive unreadable");
  }

  @Test
  void oneInspectedInventoryPairIsReusableAcrossFindings() throws IOException {
    final Provider candidate =
        PrerequisiteAttributionFixtures.archive(
            directory, PrerequisiteAttributionFixtures.CANDIDATE, "shared-candidate.jar", Map.of());
    final Provider original =
        PrerequisiteAttributionFixtures.archive(
            directory,
            PrerequisiteAttributionFixtures.PROVIDER_ONE,
            "shared-original.jar",
            PrerequisiteAttributionFixtures.requiredClass());
    final Provider staged =
        PrerequisiteAttributionFixtures.archive(
            directory, PrerequisiteAttributionFixtures.PROVIDER_ONE, "shared-staged.jar", Map.of());
    final PreconditionClassInventory baseline =
        PreconditionClassInventory.complete(List.of(candidate, original));
    final PreconditionClassInventory actualFinal =
        PreconditionClassInventory.complete(List.of(candidate, staged));
    final InventoryPair pair = PreconditionProof.inspectPair(baseline, actualFinal);
    final GenericVulnerabilityFinding first =
        PrerequisiteAttributionFixtures.finding("CVE-2025-11111");
    final GenericVulnerabilityFinding second =
        PrerequisiteAttributionFixtures.finding("CVE-2025-22222");

    final PrerequisiteProofResult firstResult =
        PreconditionProof.proveWithAttribution(
            first, PrerequisiteAttributionFixtures.CANDIDATE, pair);
    final PrerequisiteProofResult secondResult =
        PreconditionProof.proveWithAttribution(
            second, PrerequisiteAttributionFixtures.CANDIDATE, pair);

    assertAll(
        "one immutable physical inspection pair serves each finding",
        () -> assertThat(firstResult.attestation().cveId()).isEqualTo("CVE-2025-11111"),
        () -> assertThat(secondResult.attestation().cveId()).isEqualTo("CVE-2025-22222"),
        () ->
            assertThat(firstResult.attestation().inventorySha256())
                .isEqualTo(actualFinal.fingerprint()),
        () ->
            assertThat(secondResult.attestation().inventorySha256())
                .isEqualTo(actualFinal.fingerprint()),
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(firstResult).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS),
        () ->
            assertThat(PrerequisiteAttributionFixtures.onlyGroup(secondResult).attribution())
                .isEqualTo(PrerequisiteAbsenceAttribution.TRIMMED_CLASS));
  }
}
