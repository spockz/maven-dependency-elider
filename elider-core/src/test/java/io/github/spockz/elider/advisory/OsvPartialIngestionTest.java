/* WHY: Verifies malformed OSV records do not discard independent advisory owners. */

package io.github.spockz.elider.advisory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import com.sun.net.httpserver.HttpServer;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises independent OSV records through the persisted generic source cache. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidDuplicateLiterals",
  "PMD.ShortVariable",
  "PMD.AvoidLiteralsInIfCondition",
  "PMD.LawOfDemeter"
})
class OsvPartialIngestionTest {
  private static final CacheProducerIdentity PRODUCER =
      new CacheProducerIdentity("io.github.spockz", "dependency-elider", "1.0.0", null);
  @TempDir Path directory;

  @Test
  void malformedSnapshotRecordKeepsValidSiblingAndPartialStateOffline() throws Exception {
    final byte[] zip =
        SnapshotZipFixtures.raw(
            "GHSA-good.json", record("GHSA-good", "1.0"), "GHSA-bad.json", "{malformed");
    final AtomicReference<String> changes = new AtomicReference<>("");
    final AtomicReference<String> replacement = new AtomicReference<>("{malformed");
    final HttpServer server = server(zip, changes, replacement);
    server.start();
    try {
      final URI uri = endpoint(server);
      final GenericFindingCacheManager manager = new GenericFindingCacheManager();
      final GenericFindingCacheManager.CacheResult refreshed = manager.load(config(uri, false));
      final GenericFindingCacheManager.CacheResult offline = manager.load(config(uri, true));
      assertAll(
          () -> assertThat(refreshed.refreshFailure()).isEmpty(),
          () ->
              assertThat(refreshed.envelope())
                  .isPresent()
                  .get()
                  .satisfies(
                      envelope -> {
                        assertThat(envelope.sources().get(FindingSource.OSV).status())
                            .isEqualTo(FindingSourceSnapshot.Status.PARTIAL);
                        assertThat(envelope.sources().get(FindingSource.OSV).diagnostic())
                            .contains("1");
                        assertThat(envelope.contributions())
                            .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                            .contains("GHSA-good");
                      }),
          () -> assertThat(offline.envelope()).isEqualTo(refreshed.envelope()));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void conflictingOwnersAndInvalidWithdrawalsAreSkippedWithoutChoosingAnOrder() throws Exception {
    final String malformedWithdrawal =
        "{\"id\":\"GHSA-invalid-withdrawal\",\"modified\":\"2026-11-04T10:00:00Z\","
            + "\"withdrawn\":false}";
    final byte[] zip =
        SnapshotZipFixtures.raw(
            "one.json",
            record("GHSA-duplicate", "1.0"),
            "two.json",
            record("GHSA-duplicate", "2.0"),
            "withdrawn.json",
            malformedWithdrawal,
            "good.json",
            record("GHSA-good", "1.0"));
    final HttpServer server = server(zip, new AtomicReference<>(""), new AtomicReference<>(""));
    server.start();
    try {
      final GenericFindingCacheManager.CacheResult result =
          new GenericFindingCacheManager().load(config(endpoint(server), false));
      assertAll(
          () -> assertThat(result.refreshFailure()).isEmpty(),
          () ->
              assertThat(result.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(
                      result.envelope().orElseThrow().sources().get(FindingSource.OSV).diagnostic())
                  .contains("3"),
          () ->
              assertThat(result.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void duplicateOwnerCannotBeResurrectedByOlderDeltaInEitherZipOrder() throws Exception {
    final String active = record("GHSA-duplicate", "1.0");
    final String withdrawal =
        "{\"id\":\"GHSA-duplicate\",\"modified\":\"2026-11-05T12:00:00Z\","
            + "\"withdrawn\":\"2026-11-05T12:00:00Z\"}";
    assertAll(
        () -> assertAmbiguousOwnerRemainsAbsent("active-first", active, withdrawal),
        () -> assertAmbiguousOwnerRemainsAbsent("withdrawal-first", withdrawal, active));
  }

  private void assertAmbiguousOwnerRemainsAbsent(
      final String name, final String first, final String second) throws IOException {
    final byte[] zip =
        SnapshotZipFixtures.raw(
            "one.json", first, "two.json", second, "good.json", record("GHSA-good", "1.0"));
    final AtomicReference<String> changes =
        new AtomicReference<>("2026-11-04T11:00:00Z,GHSA-duplicate\n");
    final HttpServer server =
        server(zip, changes, new AtomicReference<>(record("GHSA-duplicate", "2.0")));
    server.start();
    try {
      final URI uri = endpoint(server);
      final VulnerabilityCacheManager.CacheConfig config =
          new VulnerabilityCacheManager.CacheConfig(
              directory.resolve(name),
              uri,
              null,
              Duration.ZERO,
              false,
              false,
              VulnerabilityCacheManager.bundledEmptySeed(),
              PRODUCER);
      final GenericFindingCacheManager.CacheResult result =
          new GenericFindingCacheManager().load(config);
      assertAll(
          name,
          () ->
              assertThat(result.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(result.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void withdrawnOwnerRejectsOlderDeltaAcrossWarmCacheAndAllowsNewerUpdate() throws Exception {
    final String withdrawn =
        "{\"id\":\"GHSA-withdrawn\",\"modified\":\"2026-11-05T12:00:00Z\","
            + "\"withdrawn\":\"2026-11-05T12:00:00Z\"}";
    final byte[] zip =
        SnapshotZipFixtures.raw(
            "withdrawn.json", withdrawn, "good.json", record("GHSA-good", "1.0"));
    final AtomicReference<String> changes =
        new AtomicReference<>("2026-11-04T11:00:00Z,GHSA-withdrawn\n");
    final AtomicReference<String> replacement =
        new AtomicReference<>(record("GHSA-withdrawn", "2.0"));
    final HttpServer server = server(zip, changes, replacement);
    server.start();
    try {
      final URI uri = endpoint(server);
      final GenericFindingCacheManager manager = new GenericFindingCacheManager();
      final GenericFindingCacheManager.CacheResult first = manager.load(config(uri, false));
      final GenericFindingCacheManager.CacheResult warm = manager.load(config(uri, false));
      changes.set("2026-11-06T10:00:00Z,GHSA-withdrawn\n");
      replacement.set(
          record("GHSA-withdrawn", "2.0").replace("2026-11-05T10:00:00Z", "2026-11-06T10:00:00Z"));
      final GenericFindingCacheManager.CacheResult revived = manager.load(config(uri, false));
      assertAll(
          () ->
              assertThat(first.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.CURRENT),
          () ->
              assertThat(first.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"),
          () ->
              assertThat(warm.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"),
          () ->
              assertThat(revived.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactlyInAnyOrder("GHSA-good", "GHSA-withdrawn"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void malformedKnownOwnerCannotBeResurrectedByAnOlderDelta() throws Exception {
    final String bad =
        "{\"id\":\"GHSA-duplicate\",\"modified\":\"2026-11-05T12:00:00Z\",\"withdrawn\":false}";
    final byte[] zip =
        SnapshotZipFixtures.raw("bad.json", bad, "good.json", record("GHSA-good", "1.0"));
    final AtomicReference<String> changes =
        new AtomicReference<>("2026-11-04T11:00:00Z,GHSA-duplicate\n");
    final HttpServer server =
        server(zip, changes, new AtomicReference<>(record("GHSA-duplicate", "2.0")));
    server.start();
    try {
      final GenericFindingCacheManager.CacheResult result =
          new GenericFindingCacheManager().load(config(endpoint(server), false));
      assertAll(
          () ->
              assertThat(result.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(result.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void malformedAffectedEntryDoesNotDiscardValidSiblingPackage() throws Exception {
    final String advisory =
        """
        {"id":"GHSA-mixed","modified":"2026-11-04T10:00:00Z","affected":[
          {"package":{"ecosystem":"Maven","name":"org.example:good"},"versions":["1.0"]},
          {"package":{"ecosystem":"Maven","name":"org.example:bad"},"versions":[42]}
        ]}
        """;
    final HttpServer server =
        server(
            SnapshotZipFixtures.raw("GHSA-mixed.json", advisory),
            new AtomicReference<>(""),
            new AtomicReference<>(""));
    server.start();
    try {
      final GenericFindingCacheManager.CacheResult result =
          new GenericFindingCacheManager().load(config(endpoint(server), false));
      assertAll(
          () -> assertThat(result.refreshFailure()).isEmpty(),
          () ->
              assertThat(result.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(
                      result
                          .envelope()
                          .orElseThrow()
                          .sources()
                          .get(FindingSource.OSV)
                          .observationDiagnostics())
                  .anyMatch(value -> value.contains("affected[1]")),
          () ->
              assertThat(result.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::artifactId)
                  .containsExactly("good"));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void invalidWithdrawalOwnerDoesNotPoisonPublishedCache() throws Exception {
    final String invalid =
        "{\"id\":\"bad/id\",\"modified\":\"2026-11-05T12:00:00Z\","
            + "\"withdrawn\":\"2026-11-05T12:00:00Z\"}";
    final byte[] zip =
        SnapshotZipFixtures.raw("bad.json", invalid, "good.json", record("GHSA-good", "1.0"));
    final HttpServer server = server(zip, new AtomicReference<>(""), new AtomicReference<>(""));
    server.start();
    try {
      final GenericFindingCacheManager manager = new GenericFindingCacheManager();
      final URI uri = endpoint(server);
      final GenericFindingCacheManager.CacheResult result = manager.load(config(uri, false));
      final GenericFindingCacheManager.CacheResult offline = manager.load(config(uri, true));
      assertAll(
          () -> assertThat(result.refreshFailure()).isEmpty(),
          () ->
              assertThat(result.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(result.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"),
          () -> assertThat(offline.envelope()).isEqualTo(result.envelope()));
    } finally {
      server.stop(0);
    }
  }

  @Test
  void malformedDeltaDropsOnlyChangedOwnerAndLaterRepairClearsPartial() throws Exception {
    final byte[] zip =
        SnapshotZipFixtures.raw(
            "GHSA-good.json",
            record("GHSA-good", "1.0"),
            "GHSA-changed.json",
            record("GHSA-changed", "1.0"));
    final AtomicReference<String> changes = new AtomicReference<>("");
    final AtomicReference<String> replacement = new AtomicReference<>("{malformed");
    final HttpServer server = server(zip, changes, replacement);
    server.start();
    try {
      final GenericFindingCacheManager manager = new GenericFindingCacheManager();
      final URI uri = endpoint(server);
      final GenericFindingCacheManager.CacheResult first = manager.load(config(uri, false));
      changes.set("2026-11-05T10:00:00Z,GHSA-changed\n");
      final GenericFindingCacheManager.CacheResult partial = manager.load(config(uri, false));
      replacement.set(record("GHSA-changed", "2.0"));
      final GenericFindingCacheManager.CacheResult repaired = manager.load(config(uri, false));
      assertAll(
          () -> assertThat(first.envelope().orElseThrow().contributions()).hasSize(2),
          () ->
              assertThat(partial.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.PARTIAL),
          () ->
              assertThat(partial.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactly("GHSA-good"),
          () ->
              assertThat(
                      repaired.envelope().orElseThrow().sources().get(FindingSource.OSV).status())
                  .isEqualTo(FindingSourceSnapshot.Status.CURRENT),
          () ->
              assertThat(repaired.envelope().orElseThrow().contributions())
                  .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                  .containsExactlyInAnyOrder("GHSA-good", "GHSA-changed"));
    } finally {
      server.stop(0);
    }
  }

  private VulnerabilityCacheManager.CacheConfig config(final URI uri, final boolean offline) {
    return new VulnerabilityCacheManager.CacheConfig(
        directory.resolve("cache"),
        uri,
        null,
        Duration.ZERO,
        false,
        offline,
        VulnerabilityCacheManager.bundledEmptySeed(),
        PRODUCER);
  }

  private static String record(final String id, final String version) {
    final String template =
        """
        {"id":"%s","modified":"%s","affected":[
          {"package":{"ecosystem":"Maven","name":"org.example:library"},"versions":["%s"]}]}
        """;
    return template.formatted(
        id, "2.0".equals(version) ? "2026-11-05T10:00:00Z" : "2026-11-04T10:00:00Z", version);
  }

  private static HttpServer server(
      final byte[] zip,
      final AtomicReference<String> changes,
      final AtomicReference<String> replacement)
      throws IOException {
    final HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    final String timestamp =
        DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(java.time.ZoneOffset.UTC));
    server.createContext(
        "/",
        exchange -> {
          final String path = exchange.getRequestURI().getPath();
          exchange.getResponseHeaders().set("Last-Modified", timestamp);
          if ("HEAD".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(200, -1);
            return;
          }
          final byte[] body =
              path.endsWith("all.zip")
                  ? zip
                  : (path.endsWith("modified_id.csv") ? changes.get() : replacement.get())
                      .getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          try (OutputStream output = exchange.getResponseBody()) {
            output.write(body);
          }
        });
    return server;
  }

  private static URI endpoint(final HttpServer server) {
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/all.zip");
  }
}
