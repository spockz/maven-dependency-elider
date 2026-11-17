/* WHY: Verifies Snyk package queries stay exact-version scoped and fail visibly. */

package io.github.spockz.elider.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.EvidenceOrigin;
import io.github.spockz.elider.model.VersionApplicability;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** Verifies authenticated Snyk package queries and their conservative findings. */
@SuppressWarnings({"PMD.AvoidDuplicateLiterals", "PMD.TooManyMethods"})
class SnykPackageIssuesClientTest {
  /** Fixture authorization value for the local HTTP server. */
  private static final String TOKEN = "snyk-test-secret";

  /** Exact package coordinate shared by the client scenarios. */
  private static final ArtifactCoordinate COORDINATE =
      ArtifactCoordinate.of("com.example.group", "library", "1.0");

  /** Creates the test fixture. */
  /* package */ SnykPackageIssuesClientTest() {
    super();
  }

  @Test
  @SuppressWarnings("PMD.LawOfDemeter")
  void queryKeepsExactCoordinateAndPreservesSnykAndCveIdentity() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[
            {"id":"SNYK-JAVA-COMEXAMPLE-1001","type":"issue","attributes":{"type":"package_vulnerability","problems":[{"id":"CVE-2024-10001","source":"CVE"},{"id":"CVE-2024-10001","source":"CVE"}]}},
            {"id":"SNYK-JAVA-COMEXAMPLE-1002","type":"issue","attributes":{"type":"package_vulnerability","problems":[{"id":"CVE-2024-10002","source":"CVE"}]}}
          ],"meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},"links":{"self":"/rest/orgs/test-org/packages/pkg%3Amaven%2Fcom.example.group%2Flibrary%401.0/issues?version=2024-06-26&offset=0"}}\
          """);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "one exact query retains issue identity, scope and provenance",
          () -> assertThat(result.coordinate()).isEqualTo(COORDINATE),
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.COMPLETE),
          () -> assertThat(result.contributions()).hasSize(2),
          () ->
              assertThat(result.contributions().getFirst().vulnerabilityId())
                  .isEqualTo("SNYK-JAVA-COMEXAMPLE-1001"),
          () ->
              assertThat(result.contributions().getFirst().aliases())
                  .containsExactly("CVE-2024-10001"),
          () ->
              assertThat(result.contributions().getFirst().versionClaims())
                  .singleElement()
                  .satisfies(
                      claim ->
                          assertAll(
                              () -> assertThat(claim.normalizedMavenRange()).isEqualTo("[1.0]"),
                              () ->
                                  assertThat(claim.status())
                                      .isEqualTo(VersionApplicability.AFFECTED))),
          () -> assertThat(result.contributions().getFirst().codeGroup().supplied()).isFalse(),
          () ->
              assertThat(result.contributions().getFirst().prerequisiteGroup().supplied())
                  .isFalse(),
          () ->
              assertThat(result.contributions().getFirst().intent())
                  .isEqualTo(io.github.spockz.elider.model.AssessmentIntent.AUTO_VERIFY),
          () ->
              assertThat(result.contributions().getFirst().sourceProvenance())
                  .singleElement()
                  .satisfies(
                      provenance ->
                          assertAll(
                              () -> assertThat(provenance.origin()).isEqualTo(EvidenceOrigin.SNYK),
                              () ->
                                  assertThat(provenance.sourceRecordId())
                                      .isEqualTo("SNYK-JAVA-COMEXAMPLE-1001"),
                              () ->
                                  assertThat(provenance.sourceUrl().toString())
                                      .isEqualTo(
                                          "https://security.snyk.io/vuln/SNYK-JAVA-COMEXAMPLE-1001"))),
          () ->
              assertThat(server.requestPath())
                  .contains("pkg%3Amaven%2Fcom.example.group%2Flibrary%401.0"),
          () -> assertThat(server.requestPath()).contains("version=2024-06-26"),
          () -> assertThat(server.authorization()).isEqualTo("token " + TOKEN));
    }
  }

  @Test
  void malformedIssueRowsAreSkippedIndividuallyAndMarkTheResultPartial() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[
            {"id":"SNYK-JAVA-COMEXAMPLE-2001","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}},
            {"type":"issue","attributes":{"problems":[]}},
            {"id":"SNYK-JAVA-COMEXAMPLE-2003","type":"issue","attributes":{"type":"package_vulnerability","problems":"malformed"}},
            {"id":"SNYK-JAVA-LICENSE","type":"issue","attributes":{"type":"license","problems":[{"id":"CVE-2024-10003","source":"CVE"}]}}
          ],"meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}}}
          """);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "malformed rows do not discard valid rows",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () -> assertThat(result.contributions()).hasSize(1),
          () ->
              assertThat(result.contributions().getFirst().vulnerabilityId())
                  .isEqualTo("SNYK-JAVA-COMEXAMPLE-2001"),
          () -> assertThat(result.diagnostics()).isNotEmpty(),
          () -> assertThat(String.join(" ", result.diagnostics())).doesNotContain(TOKEN));
    }
  }

  @Test
  void unrelatedLicenseIssueIsNotReportedAsVulnerability() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[{"id":"SNYK-JAVA-LICENSE","type":"issue","attributes":{"type":"license","problems":[{"id":"CVE-2024-10003","source":"CVE"}]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}}}
          """);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "non-vulnerability issue data is not projected into vulnerability findings",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () -> assertThat(result.contributions()).isEmpty(),
          () ->
              assertThat(result.diagnostics())
                  .anyMatch(value -> value.contains("unsupported issue type")));
    }
  }

  @Test
  void followsSameEndpointPaginationAndAggregatesRows() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      final AtomicInteger calls = new AtomicInteger();
      server.handle(
          exchange -> {
            calls.incrementAndGet();
            if (exchange.getRequestURI().getRawQuery().contains("offset=0")) {
              SnykPackageIssuesTestSupport.SnykHttpFixture.reply(
                  exchange,
                  200,
                  """
                  {"data":[{"id":"SNYK-JAVA-ONE","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
                   "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},
                   "links":{"next":"/orgs/test-org/packages/pkg%3Amaven%2fcom.example.group%2flibrary%401.0/issues?version=2024-06-26&limit=1&offset=1"}}
                  """);
            } else {
              SnykPackageIssuesTestSupport.SnykHttpFixture.reply(
                  exchange,
                  200,
                  """
                  {"data":[{"id":"SNYK-JAVA-TWO","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
                   "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}}}
                  """);
            }
          });

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "both pages are returned for one endpoint",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.COMPLETE),
          () ->
              assertThat(result.contributions())
                  .extracting(
                      io.github.spockz.elider.model.VulnerabilityFindingContribution
                          ::vulnerabilityId)
                  .containsExactly("SNYK-JAVA-ONE", "SNYK-JAVA-TWO"),
          () -> assertThat(calls).hasValue(2));
    }
  }

  @Test
  void crossOriginPaginationIsRejectedWithoutForwardingCredentials() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[{"id":"SNYK-JAVA-ONE","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},
           "links":{"next":"https://attacker.example/rest/orgs/test-org/packages/x/issues?version=2024-06-26&offset=100"}}
          """);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "cross-origin pagination is not followed",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () -> assertThat(result.contributions()).hasSize(1),
          () -> assertThat(server.requestCount()).isEqualTo(1),
          () ->
              assertThat(String.join(" ", result.diagnostics()))
                  .doesNotContain(TOKEN, "attacker.example"));
    }
  }

  @Test
  void offsetJumpCannotProduceCompleteResultWhenRowsWouldBeSkipped() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      final AtomicInteger calls = new AtomicInteger();
      server.handle(
          exchange -> {
            calls.incrementAndGet();
            SnykPackageIssuesTestSupport.SnykHttpFixture.reply(
                exchange,
                200,
                """
                {"data":[{"id":"SNYK-JAVA-ONE","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
                 "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},
                 "links":{"next":"/orgs/test-org/packages/pkg%3Amaven%2Fcom.example.group%2Flibrary%401.0/issues?version=2024-06-26&limit=1000&offset=1000"}}
                """);
          });

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "offset gaps leave the response partial and stop pagination",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () -> assertThat(result.contributions()).hasSize(1),
          () -> assertThat(result.diagnostics()).isNotEmpty(),
          () -> assertThat(calls).hasValue(1));
    }
  }

  @Test
  void malformedPresentLinksFieldMarksThePagePartialButKeepsItsFindings() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[{"id":"SNYK-JAVA-ONE","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},
           "links":"malformed"}
          """);
      final SnykPackageIssuesClient client = client(server);
      final SnykPackageIssuesResult malformedObject = client.query(COORDINATE);

      server.respond(
          200,
          """
          {"data":[{"id":"SNYK-JAVA-TWO","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}},
           "links":null}
          """);
      final SnykPackageIssuesResult malformedNull = client.query(COORDINATE);

      assertAll(
          "malformed links are reported without discarding page findings",
          () ->
              assertThat(malformedObject.status())
                  .isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () ->
              assertThat(malformedNull.status()).isEqualTo(SnykPackageIssuesResult.Status.PARTIAL),
          () ->
              assertThat(malformedObject.contributions())
                  .extracting(
                      io.github.spockz.elider.model.VulnerabilityFindingContribution
                          ::vulnerabilityId)
                  .containsExactly("SNYK-JAVA-ONE"),
          () ->
              assertThat(malformedNull.contributions())
                  .extracting(
                      io.github.spockz.elider.model.VulnerabilityFindingContribution
                          ::vulnerabilityId)
                  .containsExactly("SNYK-JAVA-TWO"),
          () -> assertThat(malformedObject.diagnostics()).isNotEmpty(),
          () -> assertThat(malformedNull.diagnostics()).isNotEmpty());
    }
  }

  @Test
  void httpFailureIsExplicitAndDoesNotExposeResponseBodyOrToken() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(403, "private response body " + TOKEN);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "HTTP failures expose neither findings nor response secrets",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(result.contributions()).isEmpty(),
          () ->
              assertThat(String.join(" ", result.diagnostics()))
                  .doesNotContain(TOKEN, "private response body"));
    }
  }

  @Test
  void mismatchedResponsePackageMetadataFailsTheExactVersionQuery() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[{"id":"SNYK-JAVA-WRONG","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0.0","version":"1.0.0"}}}
          """);

      final SnykPackageIssuesResult result = client(server).query(COORDINATE);

      assertAll(
          "metadata for a Maven-equivalent version cannot be substituted",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(result.contributions()).isEmpty());
    }
  }

  @Test
  void duplicateJsonKeysAndTrailingDocumentsFailExplicitly() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      server.respond(
          200,
          """
          {"data":[],"data":[{"id":"SNYK-JAVA-ONE","type":"issue","attributes":{"type":"package_vulnerability","problems":[]}}],
           "meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}}}
          """);
      final SnykPackageIssuesClient client = client(server);
      final SnykPackageIssuesResult duplicateKeyResult = client.query(COORDINATE);

      server.respond(
          200,
          """
          {"data":[],"meta":{"package":{"name":"library","type":"maven","url":"pkg:maven/com.example.group/library@1.0","version":"1.0"}}}
          {"data":[]}
          """);
      final SnykPackageIssuesResult trailingDocumentResult = client.query(COORDINATE);

      assertAll(
          "ambiguous JSON documents fail rather than becoming findings",
          () ->
              assertThat(duplicateKeyResult.status())
                  .isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () ->
              assertThat(trailingDocumentResult.status())
                  .isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(duplicateKeyResult.contributions()).isEmpty(),
          () -> assertThat(trailingDocumentResult.contributions()).isEmpty());
    }
  }

  @Test
  void differentVersionQueriesRemainDistinctEvenWhenMavenConsidersThemEquivalent() {
    final ArtifactCoordinate alternate =
        ArtifactCoordinate.of("com.example.group", "library", "1.0.0");
    assertThat(COORDINATE).isNotEqualTo(alternate);
  }

  @Test
  void unsupportedArtifactTypeAndClassifierFailWithoutIssuingRequests() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      final SnykPackageIssuesClient client = client(server);
      final ArtifactCoordinate nonJar =
          new ArtifactCoordinate("com.example.group", "library", "1.0", "pom", "", "compile");
      final ArtifactCoordinate classified =
          new ArtifactCoordinate("com.example.group", "library", "1.0", "jar", "tests", "test");

      final SnykPackageIssuesResult nonJarResult = client.query(nonJar);
      final SnykPackageIssuesResult classifiedResult = client.query(classified);
      final int requests = server.requestCount();

      assertAll(
          "unsupported Maven variants fail before network access",
          () -> assertThat(nonJarResult.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () ->
              assertThat(classifiedResult.status())
                  .isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(nonJarResult.diagnostics()).isNotEmpty(),
          () -> assertThat(classifiedResult.diagnostics()).isNotEmpty(),
          () -> assertEquals(0, requests, "no HTTP requests should be issued"));
    }
  }

  @Test
  void missingOrBlankCandidateVersionsFailExplicitly() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      final SnykPackageIssuesClient client = client(server);
      final ArtifactCoordinate missing =
          ArtifactCoordinate.of("com.example.group", "library", null);
      final ArtifactCoordinate blank = ArtifactCoordinate.of("com.example.group", "library", " ");

      final SnykPackageIssuesResult missingResult = client.query(missing);
      final SnykPackageIssuesResult blankResult = client.query(blank);
      final int requests = server.requestCount();

      assertAll(
          "missing candidate versions fail explicitly before network access",
          () -> assertThat(missingResult.coordinate()).isEqualTo(missing),
          () -> assertThat(blankResult.coordinate()).isEqualTo(blank),
          () -> assertThat(missingResult.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(blankResult.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertEquals(0, requests, "no HTTP requests should be issued"));
    }
  }

  @Test
  void malformedAuthorizationTokenFailsWithoutLeakingTheHeaderValue() throws IOException {
    try (SnykPackageIssuesTestSupport.SnykHttpFixture server =
        new SnykPackageIssuesTestSupport.SnykHttpFixture()) {
      final String malformedToken = "secret-token\r\nAuthorization: attacker-value";
      final SnykPackageIssuesClient client =
          new SnykPackageIssuesClient(server.baseUri(), "test-org", malformedToken);

      final SnykPackageIssuesResult result = client.query(COORDINATE);
      final int requests = server.requestCount();

      assertAll(
          "malformed credential data fails without header injection or disclosure",
          () -> assertThat(result.status()).isEqualTo(SnykPackageIssuesResult.Status.FAILED),
          () -> assertThat(result.contributions()).isEmpty(),
          () ->
              assertThat(String.join(" ", result.diagnostics()))
                  .doesNotContain(malformedToken, "attacker-value"),
          () -> assertEquals(0, requests, "no HTTP requests should be issued"));
    }
  }

  private static SnykPackageIssuesClient client(
      final SnykPackageIssuesTestSupport.SnykHttpFixture server) {
    return new SnykPackageIssuesClient(server.baseUri(), "test-org", TOKEN);
  }
}
