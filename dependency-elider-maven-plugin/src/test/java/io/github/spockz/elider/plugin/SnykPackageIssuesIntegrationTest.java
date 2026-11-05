// WHY: Verifies opt-in Snyk query lifecycle and exact Maven coordinate scoping.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.GenericFindingReconciler;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import io.github.spockz.elider.scanner.FindingSource;
import io.github.spockz.elider.scanner.SnykPackageIssuesResult;
import io.github.spockz.elider.scanner.SnykPackageIssuesResult.Status;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Tests optional Snyk queries and their source reporting. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.AvoidDuplicateLiterals"
})
final class SnykPackageIssuesIntegrationTest {
  @Test
  void disabledIntegrationDoesNotQueryOrCreateSourceObservation() {
    final List<ArtifactCoordinate> queried = new ArrayList<>();

    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            List.of(ArtifactCoordinate.of("org.example", "demo", "1.0")),
            false,
            false,
            "org-id",
            "secret-token",
            coordinate -> {
              queried.add(coordinate);
              throw new AssertionError("disabled Snyk integration must not query");
            });

    assertThat(queried).isEmpty();
    assertThat(result.results()).isEmpty();
    assertThat(result.observation()).isEmpty();
  }

  @Test
  void offlineIntegrationReportsUnavailableWithoutCallingTheQuery() {
    final List<ArtifactCoordinate> queried = new ArrayList<>();

    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            List.of(ArtifactCoordinate.of("org.example", "demo", "1.0")),
            true,
            true,
            "org-id",
            "secret-token",
            coordinate -> {
              queried.add(coordinate);
              throw new AssertionError("offline Snyk integration must not query");
            });

    assertThat(queried).isEmpty();
    assertThat(result.observation())
        .get()
        .satisfies(
            observation -> {
              assertThat(observation.source()).contains(FindingSource.SNYK);
              assertThat(observation.status())
                  .isEqualTo(FindingSourceObservation.Status.UNAVAILABLE);
              assertThat(observation.diagnostic()).contains("offline");
            });
  }

  @Test
  void queriesDistinctExactCoordinatesAndReportsPartialFailureWithoutCredentials() {
    final ArtifactCoordinate one = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final ArtifactCoordinate equivalent = ArtifactCoordinate.of("org.example", "demo", "1.0.0");
    final List<ArtifactCoordinate> queried = new ArrayList<>();

    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            List.of(one, equivalent, one),
            true,
            false,
            "org-secret-org-id",
            "secret-token",
            coordinate -> {
              queried.add(coordinate);
              if (coordinate.equals(one)) {
                return new SnykPackageIssuesResult(one, Status.COMPLETE, List.of(), List.of());
              }
              return new SnykPackageIssuesResult(
                  equivalent, Status.FAILED, List.of(), List.of("secret-token org-secret-org-id"));
            });

    assertThat(queried).containsExactly(one, equivalent);
    assertThat(result.results().keySet()).containsExactlyInAnyOrder(one, equivalent);
    assertThat(result.results().get(one).status()).isEqualTo(Status.COMPLETE);
    assertThat(result.results().get(equivalent).status()).isEqualTo(Status.FAILED);
    assertThat(result.observation())
        .get()
        .satisfies(
            observation -> {
              assertThat(observation.source()).contains(FindingSource.SNYK);
              assertThat(observation.status()).isEqualTo(FindingSourceObservation.Status.PARTIAL);
              assertThat(observation.diagnostic())
                  .doesNotContain("secret-token", "org-secret-org-id");
              assertThat(observation.observationDiagnostics())
                  .singleElement()
                  .satisfies(
                      diagnostic -> {
                        assertThat(diagnostic).contains("org.example:demo:jar:1.0.0");
                        assertThat(diagnostic).doesNotContain("secret-token", "org-secret-org-id");
                      });
              assertThat(observation.revision()).isNotBlank();
            });
  }

  @Test
  void exactCoordinateLookupDoesNotReuseMavenEquivalentVersionResults() {
    final ArtifactCoordinate one = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final ArtifactCoordinate equivalent = ArtifactCoordinate.of("org.example", "demo", "1.0.0");
    final VulnerabilityFindingContribution contribution = contribution(one);
    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            List.of(one),
            true,
            false,
            "org-id",
            "token",
            coordinate ->
                new SnykPackageIssuesResult(
                    coordinate, Status.COMPLETE, List.of(contribution), List.of()));

    assertThat(result.contributionsFor(one)).containsExactly(contribution);
    assertThat(result.contributionsFor(equivalent)).isEmpty();
  }

  @Test
  void candidateReconciliationKeepsSnykEvidenceOnOnlyItsExactQueriedVersion() {
    final ArtifactCoordinate one = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final ArtifactCoordinate equivalent = ArtifactCoordinate.of("org.example", "demo", "1.0.0");
    final VulnerabilityFindingContribution base = contribution(one).withProvenance("shared base");
    final VulnerabilityFindingContribution snyk = contribution(one);
    final SnykPackageIssuesIntegration.Result snykResults =
        SnykPackageIssuesIntegration.collect(
            List.of(one, equivalent),
            true,
            false,
            "org-id",
            "token",
            coordinate ->
                new SnykPackageIssuesResult(
                    coordinate,
                    Status.COMPLETE,
                    coordinate.equals(one) ? List.of(snyk) : List.of(),
                    List.of()));

    final Map<ArtifactCoordinate, List<io.github.spockz.elider.model.GenericVulnerabilityFinding>>
        findings =
            MavenVulnerabilityAssessment.candidateFindings(
                List.of(base),
                GenericFindingReconciler.reconcile(List.of(base)).findings(),
                List.of(one, equivalent),
                snykResults);

    assertThat(findings.get(one))
        .singleElement()
        .satisfies(finding -> assertThat(finding.contributions()).hasSize(2));
    assertThat(findings.get(equivalent))
        .singleElement()
        .satisfies(finding -> assertThat(finding.contributions()).containsExactly(base));
  }

  @Test
  void permitsOfficialRegionalOriginsAndRejectsTokenDestinationsOutsideTheAllowlist() {
    assertThat(SnykPackageIssuesIntegration.validateApiBaseUri("https://api.eu.snyk.io"))
        .isEqualTo(java.net.URI.create("https://api.eu.snyk.io"));
    assertThat(SnykPackageIssuesIntegration.validateApiBaseUri("https://api.au.snyk.io"))
        .isEqualTo(java.net.URI.create("https://api.au.snyk.io"));
    org.junit.jupiter.api.Assertions.assertAll(
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> SnykPackageIssuesIntegration.validateApiBaseUri("https://attacker.example")),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () ->
                    SnykPackageIssuesIntegration.validateApiBaseUri(
                        "https://api.snyk.io.evil.example")),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> SnykPackageIssuesIntegration.validateApiBaseUri("https://user@api.snyk.io")),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> SnykPackageIssuesIntegration.validateApiBaseUri("https://api.snyk.io:8443")),
        () ->
            org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> SnykPackageIssuesIntegration.validateApiBaseUri("https://api.snyk.io/path")));
  }

  @Test
  void retainsSafeHttpFailureReasonsInSourceObservationDiagnostics() {
    final ArtifactCoordinate coordinate = ArtifactCoordinate.of("org.example", "demo", "1.0");
    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            List.of(coordinate),
            true,
            false,
            "org-id",
            "token",
            candidate ->
                new SnykPackageIssuesResult(
                    candidate,
                    Status.FAILED,
                    List.of(),
                    List.of("Snyk request failed with HTTP status 429")));

    assertThat(result.observation())
        .get()
        .satisfies(
            observation -> {
              assertThat(observation.status()).isEqualTo(FindingSourceObservation.Status.ERROR);
              assertThat(observation.observationDiagnostics())
                  .singleElement()
                  .satisfies(
                      diagnostic ->
                          assertThat(diagnostic).contains("HTTP status 429", coordinate.toId()));
            });
  }

  @Test
  void preservesSafeClientValidationAndUnsupportedIssueReasons() {
    final List<String> clientReasons =
        List.of(
            "Snyk authorization token is invalid",
            "Snyk package query requires an exact version",
            "Snyk package query requires Maven group and artifact identifiers",
            "Snyk package query does not support this Maven type or classifier",
            "Snyk issue row 4 had an unsupported issue type");
    final List<ArtifactCoordinate> candidates =
        java.util.stream.IntStream.range(0, clientReasons.size())
            .mapToObj(index -> ArtifactCoordinate.of("org.example", "lib-" + index, "1.0"))
            .toList();
    final SnykPackageIssuesIntegration.Result result =
        SnykPackageIssuesIntegration.collect(
            candidates,
            true,
            false,
            "org-secret-org-id",
            "secret-token",
            coordinate ->
                new SnykPackageIssuesResult(
                    coordinate,
                    Status.FAILED,
                    List.of(),
                    List.of(
                        clientReasons.get(
                            Integer.parseInt(coordinate.artifactId().substring(4))))));

    assertThat(result.observation())
        .get()
        .satisfies(
            observation -> {
              assertThat(observation.status()).isEqualTo(FindingSourceObservation.Status.ERROR);
              assertThat(observation.observationDiagnostics())
                  .anySatisfy(
                      reason -> assertThat(reason).contains("authorization token is invalid"))
                  .anySatisfy(reason -> assertThat(reason).contains("requires an exact version"))
                  .anySatisfy(
                      reason -> assertThat(reason).contains("group and artifact identifiers"))
                  .anySatisfy(reason -> assertThat(reason).contains("type or classifier"))
                  .anySatisfy(
                      reason -> assertThat(reason).contains("row 4 had an unsupported issue type"));
              assertThat(observation.observationDiagnostics())
                  .noneMatch(
                      reason ->
                          reason.contains("secret-token") || reason.contains("org-secret-org-id"));
            });
  }

  @Test
  void persistsSnykSourceAttributionInTheElisionReportCodec() throws java.io.IOException {
    final FindingSourceObservation observation =
        new FindingSourceObservation(
            Optional.of(FindingSource.SNYK),
            FindingSourceObservation.Status.CURRENT,
            "a".repeat(64),
            Instant.parse("2026-11-05T00:00:00Z"),
            null,
            List.of(),
            2);

    final List<FindingSourceObservation> decoded =
        MavenElisionReportGenericPayload.readObservations(
            MavenElisionReportGenericPayload.observations(List.of(observation)));

    assertThat(decoded).containsExactly(observation);
  }

  private static VulnerabilityFindingContribution contribution(
      final ArtifactCoordinate coordinate) {
    return new VulnerabilityFindingContribution(
        "SNYK-JAVA-TEST",
        Set.of(),
        coordinate.groupId(),
        coordinate.artifactId(),
        coordinate.type(),
        coordinate.classifier(),
        List.of(VersionCoverageClaim.affected("[1.0]")),
        FieldValue.omitted(),
        FieldValue.omitted(),
        MergePriority.AUTOMATIC,
        AssessmentIntent.REVIEW_ONLY,
        "Snyk package issues",
        Set.of());
  }
}
