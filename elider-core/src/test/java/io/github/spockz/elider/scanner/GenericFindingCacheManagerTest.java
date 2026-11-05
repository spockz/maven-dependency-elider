/* WHY: Verifies offline finding replay. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.spockz.elider.model.AssessmentIntent;
import io.github.spockz.elider.model.CacheProducerIdentity;
import io.github.spockz.elider.model.FieldValue;
import io.github.spockz.elider.model.MergePriority;
import io.github.spockz.elider.model.VersionApplicability;
import io.github.spockz.elider.model.VersionCoverageClaim;
import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies independent refresh, offline reuse and explicit failure observations. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.TooManyMethods", "PMD.AvoidDuplicateLiterals"})
// Source labels sit beside the lifecycle scenarios that exercise them.
class GenericFindingCacheManagerTest {
  /** Producer identity shared by these immutable cache fixtures. */
  private static final CacheProducerIdentity PRODUCER =
      new CacheProducerIdentity("io.github.spockz", "dependency-elider", "1.0.0", null);

  /** Isolates each test's checkout and published cache. */
  @TempDir /* default */ Path tempDir;

  @Test
  void offlineLoadReplaysGenericContributionsWithoutContactingEitherSource() throws IOException {
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    final VulnerabilityFindingContribution cve = contribution("CVE-2026-12345", "cve");
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(
                FindingSource.OSV,
                current(FindingSource.OSV, "osv-revision-1", osv),
                FindingSource.CVE_LIST,
                current(FindingSource.CVE_LIST, "cve-revision-1", cve)));
    Files.write(
        tempDir.resolve("index.json"), new GenericFindingCacheEnvelopeWriter().encode(envelope));
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            tempDir,
            URI.create("https://invalid.example/osv/all.zip"),
            URI.create("https://invalid.example/cve.git"),
            Duration.ZERO,
            true,
            true,
            () -> new ByteArrayInputStream(new byte[0]),
            PRODUCER);

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);

    assertAll(
        () ->
            assertThat(result.contributions())
                .extracting(VulnerabilityFindingContribution::provenance)
                .containsExactlyInAnyOrder("osv", "cve"),
        () -> assertThat(result.source()).isEqualTo(GenericFindingCacheManager.Source.CACHE),
        () -> assertThat(result.refreshFailure()).isEmpty());
  }

  @Test
  void timedGitCaptureDoesNotWaitForAnUnclosedOutputStream()
      throws IOException, InterruptedException {
    Assumptions.assumeFalse(System.getProperty("os.name").toLowerCase(Locale.ROOT).contains("win"));
    final Instant started = Instant.now();

    final GenericFindingCacheManager.GitCommandResult result =
        GenericFindingCacheManager.captureGitOutput(
            new ProcessBuilder("sleep", "30"), Duration.ofMillis(100));
    final boolean completed = result.completed();
    final boolean processAlive = result.processAlive();

    assertAll(
        "a timed out Git process must not hold the output reader open",
        () -> assertFalse(completed, "the capture should report a timed-out process"),
        () -> assertFalse(processAlive, "the timed-out process should be stopped"),
        () ->
            assertThat(Duration.between(started, Instant.now())).isLessThan(Duration.ofSeconds(5)));
  }

  @Test
  void freshCvePartitionReusesTrustedRevisionWithoutGitContactOrRescan() throws IOException {
    final VulnerabilityFindingContribution cve = contribution("CVE-2026-12345", "cve");
    final Instant lastSuccessfulSync = Instant.now();
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(
                FindingSource.CVE_LIST,
                new FindingSourceSnapshot(
                    FindingSource.CVE_LIST,
                    "cve-revision-1",
                    lastSuccessfulSync,
                    FindingSourceSnapshot.Status.CURRENT,
                    null,
                    List.of(cve),
                    List.of())));
    Files.write(
        tempDir.resolve("index.json"), new GenericFindingCacheEnvelopeWriter().encode(envelope));
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            tempDir,
            null,
            URI.create("file:///missing-cvelist-repository.git"),
            Duration.ofHours(1),
            false,
            false,
            () -> new ByteArrayInputStream(new byte[0]),
            PRODUCER);

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);

    assertAll(
        () -> assertThat(result.refreshFailure()).isEmpty(),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.CVE_LIST).revision())
                .isEqualTo("cve-revision-1"),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.CVE_LIST).lastSuccessfulSync())
                .isEqualTo(lastSuccessfulSync),
        () -> assertThat(result.contributions()).containsExactly(cve));
  }

  @Test
  void cveWithdrawalPublishesSuccessfulEmptyPartitionAndPreservesOsvPartition()
      throws IOException, InterruptedException {
    final Path repository = initializeCveRepository("CVE-2026-12345");
    final Path cache = tempDir.resolve("cache-withdrawal");
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    writeCache(
        cache,
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", osv))));
    final VulnerabilityCacheManager.CacheConfig config =
        config(cache, repository.toUri(), Duration.ZERO, true);
    final GenericFindingCacheManager manager = new GenericFindingCacheManager();

    final GenericFindingCacheManager.CacheResult first = manager.load(config);
    Files.delete(recordPath(repository, "CVE-2026-12345"));
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "withdraw CVE");
    final GenericFindingCacheManager.CacheResult withdrawn = manager.load(config);

    assertAll(
        () -> assertThat(withdrawn.refreshFailure()).isEmpty(),
        () ->
            assertThat(envelope(first).sources().get(FindingSource.CVE_LIST).contributions())
                .hasSize(1),
        () ->
            assertThat(envelope(withdrawn).sources().get(FindingSource.CVE_LIST).status())
                .isEqualTo(FindingSourceSnapshot.Status.CURRENT),
        () ->
            assertThat(envelope(withdrawn).sources().get(FindingSource.CVE_LIST).contributions())
                .isEmpty(),
        () ->
            assertThat(envelope(withdrawn).sources().get(FindingSource.CVE_LIST).revision())
                .isNotEqualTo(envelope(first).sources().get(FindingSource.CVE_LIST).revision()),
        () ->
            assertThat(envelope(withdrawn).sources().get(FindingSource.OSV))
                .isEqualTo(envelope(first).sources().get(FindingSource.OSV)));
  }

  @Test
  void changedGitRevisionParsesOnlyChangedCveRecordAndRetainsUnchangedAssertions()
      throws IOException, InterruptedException {
    final Path repository = initializeCveRepository("CVE-2026-12345");
    writeCveRecord(repository, "CVE-2026-12346", "2.0.0");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "add second CVE");
    final Path cache = tempDir.resolve("cache-incremental");
    final VulnerabilityCacheManager.CacheConfig config =
        config(cache, repository.toUri(), Duration.ZERO, true);
    final GenericFindingCacheManager manager = new GenericFindingCacheManager();
    final GenericFindingCacheManager.CacheResult first = manager.load(config);
    writeCveRecord(repository, "CVE-2026-12345", "1.1.0");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "update one CVE");

    final GenericFindingCacheManager.CacheResult changed = manager.load(config);

    assertAll(
        () -> assertThat(first.cveRecordsParsed()).isEqualTo(2),
        () -> assertThat(changed.cveRecordsParsed()).isEqualTo(1),
        () ->
            assertThat(envelope(changed).sources().get(FindingSource.CVE_LIST).contributions())
                .extracting(VulnerabilityFindingContribution::vulnerabilityId)
                .containsExactlyInAnyOrder("CVE-2026-12345", "CVE-2026-12346"),
        () ->
            assertThat(
                    envelope(changed).sources().get(FindingSource.CVE_LIST).contributions().stream()
                        .filter(value -> "CVE-2026-12345".equals(value.vulnerabilityId()))
                        .flatMap(value -> value.versionClaims().stream())
                        .filter(claim -> claim.status() == VersionApplicability.AFFECTED)
                        .map(VersionCoverageClaim::normalizedMavenRange))
                .containsExactly("[1.1.0,1.1.0]"));
  }

  @Test
  void incrementalRefreshRetainsPriorIdentityLimitationWithoutReusingItsOldCount()
      throws IOException, InterruptedException {
    final Path repository = initializeCveRepository("CVE-2026-12345");
    writeUnmappedCveRecord(repository, "CVE-2026-12346");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "add unmapped CVE");
    final VulnerabilityCacheManager.CacheConfig config =
        config(tempDir.resolve("cache-prior-limitation"), repository.toUri(), Duration.ZERO, true);
    final GenericFindingCacheManager manager = new GenericFindingCacheManager();
    final GenericFindingCacheManager.CacheResult first = manager.load(config);
    final GenericFindingCacheManager.CacheResult unchanged = manager.load(config);
    final GenericFindingCacheManager.CacheResult unchangedAgain = manager.load(config);
    writeCveRecord(repository, "CVE-2026-12345", "1.1.0");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "change mapped CVE beside unchanged unmapped CVE");

    final GenericFindingCacheManager.CacheResult changed = manager.load(config);
    final List<String> diagnostics =
        envelope(changed).sources().get(FindingSource.CVE_LIST).observationDiagnostics();
    writeCveRecord(repository, "CVE-2026-12347", "2.1.0");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "change unrelated supported CVE");
    final GenericFindingCacheManager.CacheResult changedAgain = manager.load(config);
    final List<String> laterDiagnostics =
        envelope(changedAgain).sources().get(FindingSource.CVE_LIST).observationDiagnostics();

    assertAll(
        "incremental observations retain old limitations as unknown and report changed rows",
        () ->
            assertThat(
                    envelope(first).sources().get(FindingSource.CVE_LIST).observationDiagnostics())
                .containsExactly(
                    "1 published affected entries lacked a supported Maven package identity"),
        () ->
            assertThat(
                    envelope(unchanged)
                        .sources()
                        .get(FindingSource.CVE_LIST)
                        .observationDiagnostics())
                .contains(
                    "1 published affected entries lacked a supported Maven package identity",
                    "CVE source revision unchanged; no records parsed"),
        () ->
            assertThat(
                    envelope(unchangedAgain)
                        .sources()
                        .get(FindingSource.CVE_LIST)
                        .observationDiagnostics())
                .containsExactly(
                    "1 published affected entries lacked a supported Maven package identity",
                    "CVE source revision unchanged; no records parsed"),
        () -> assertThat(changed.cveRecordsParsed()).isEqualTo(1),
        () ->
            assertThat(diagnostics)
                .doesNotContain(
                    "1 published affected entries lacked a supported Maven package identity"),
        () ->
            assertThat(diagnostics)
                .contains(
                    "Prior CVE scan found unsupported Maven package identities; "
                        + "incremental refresh has no complete current count"),
        () -> assertThat(diagnostics).doesNotContain("2 published affected entries"),
        () ->
            assertThat(laterDiagnostics)
                .contains(
                    "Prior CVE scan found unsupported Maven package identities; "
                        + "incremental refresh has no complete current count"));
  }

  @Test
  void failedCveRefreshRetainsLastGoodClaimsAndOtherSourcePartition() throws Exception {
    final Path repository = initializeCveRepository("CVE-2026-12345");
    final Path cache = tempDir.resolve("cache-failure");
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    writeCache(
        cache,
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", osv))));
    final VulnerabilityCacheManager.CacheConfig config =
        config(cache, repository.toUri(), Duration.ZERO, true);
    final GenericFindingCacheManager manager = new GenericFindingCacheManager();
    final GenericFindingCacheManager.CacheResult first = manager.load(config);
    final Path unavailableRepository = tempDir.resolve("cve-repository-unavailable");
    Files.move(repository, unavailableRepository, StandardCopyOption.REPLACE_EXISTING);

    final GenericFindingCacheManager.CacheResult failed = manager.load(config);

    assertAll(
        () -> assertThat(failed.refreshFailure()).isPresent(),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.CVE_LIST).status())
                .isEqualTo(FindingSourceSnapshot.Status.STALE),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.CVE_LIST).contributions())
                .containsExactlyElementsOf(
                    envelope(first).sources().get(FindingSource.CVE_LIST).contributions()),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.OSV))
                .isEqualTo(envelope(first).sources().get(FindingSource.OSV)));
  }

  @Test
  void malformedCveRevisionRetainsPriorPartitionAndIndependentOsv() throws Exception {
    final String vulnerabilityId = "CVE-2026-12345";
    final Path repository = initializeCveRepository(vulnerabilityId);
    final Path cache = tempDir.resolve("cache-malformed-cve");
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    writeCache(
        cache,
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", osv))));
    final VulnerabilityCacheManager.CacheConfig config =
        config(cache, repository.toUri(), Duration.ZERO, true);
    final GenericFindingCacheManager manager = new GenericFindingCacheManager();
    final GenericFindingCacheManager.CacheResult first = manager.load(config);
    Files.writeString(
        recordPath(repository, vulnerabilityId), "{\"containers\":{},\"containers\":{}}");
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "malformed record");
    final GenericFindingCacheManager.CacheResult failed = manager.load(config);
    assertAll(
        () -> assertThat(failed.refreshFailure()).isPresent(),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.CVE_LIST).status())
                .isEqualTo(FindingSourceSnapshot.Status.STALE),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.CVE_LIST).contributions())
                .containsExactlyElementsOf(
                    envelope(first).sources().get(FindingSource.CVE_LIST).contributions()),
        () ->
            assertThat(envelope(failed).sources().get(FindingSource.OSV))
                .isEqualTo(envelope(first).sources().get(FindingSource.OSV)));
  }

  @Test
  void failedOsvRefreshDoesNotBlockCurrentCvePartition() throws Exception {
    final Path repository = initializeCveRepository("CVE-2026-12345");
    final Path cache = tempDir.resolve("cache-osv-failure");
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    writeCache(
        cache,
        new GenericFindingCacheEnvelope(
            PRODUCER,
            Map.of(FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", osv))));
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            cache,
            URI.create("http://127.0.0.1:1/osv/all.zip"),
            repository.toUri(),
            Duration.ZERO,
            true,
            false,
            () -> new ByteArrayInputStream(new byte[0]),
            PRODUCER);

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);

    assertAll(
        () -> assertThat(result.refreshFailure()).isPresent(),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.OSV).status())
                .isEqualTo(FindingSourceSnapshot.Status.STALE),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.OSV).contributions())
                .containsExactly(osv),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.CVE_LIST).status())
                .isEqualTo(FindingSourceSnapshot.Status.CURRENT),
        () ->
            assertThat(envelope(result).sources().get(FindingSource.CVE_LIST).contributions())
                .hasSize(1));
  }

  @Test
  void failedGenericPublicationReturnsPriorCacheAsAuthoritative() throws IOException {
    final VulnerabilityFindingContribution osv = contribution("GHSA-only", "osv");
    final GenericFindingCacheEnvelope envelope =
        new GenericFindingCacheEnvelope(
            PRODUCER, Map.of(FindingSource.OSV, current(FindingSource.OSV, "osv-revision-1", osv)));
    writeCache(tempDir, envelope);
    Files.createDirectories(tempDir.resolve("index.json.tmp"));
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            tempDir,
            null,
            null,
            Duration.ZERO,
            false,
            false,
            () -> new ByteArrayInputStream(new byte[0]),
            PRODUCER);

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);

    assertAll(
        () -> assertThat(result.source()).isEqualTo(GenericFindingCacheManager.Source.CACHE),
        () ->
            assertThat(result.refreshFailure())
                .hasValueSatisfying(message -> assertThat(message).contains("publication failed")),
        () -> assertThat(envelope(result)).isEqualTo(envelope));
  }

  @Test
  void missingProducerIsExplicitlyUnavailableWithoutFabricatingAnEnvelope() throws IOException {
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            tempDir,
            null,
            null,
            Duration.ZERO,
            false,
            false,
            () -> new ByteArrayInputStream(new byte[0]));

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);
    final boolean unavailable = result.source() == GenericFindingCacheManager.Source.UNAVAILABLE;
    final boolean envelopeAbsent = result.envelope().isEmpty();
    final boolean cacheFileAbsent = !Files.exists(tempDir.resolve("index.json"));

    assertAll(
        () -> assertTrue(envelopeAbsent, "missing producer data cannot form a valid envelope"),
        () -> assertTrue(unavailable, "the source state should expose unavailable cache data"),
        () ->
            assertThat(result.refreshFailure())
                .hasValueSatisfying(
                    message -> assertThat(message).contains("producer identity is unavailable")),
        () -> assertTrue(cacheFileAbsent, "unbound data must not publish a cache file"));
  }

  @Test
  void malformedOfflineGenericCacheIsExplicitlyUnavailable() throws IOException {
    Files.writeString(tempDir.resolve("index.json"), "{}");
    final VulnerabilityCacheManager.CacheConfig config =
        new VulnerabilityCacheManager.CacheConfig(
            tempDir,
            null,
            null,
            Duration.ZERO,
            false,
            true,
            () -> new ByteArrayInputStream(new byte[0]),
            PRODUCER);

    final GenericFindingCacheManager.CacheResult result =
        new GenericFindingCacheManager().load(config);

    assertAll(
        () -> assertThat(result.envelope()).isEmpty(),
        () -> assertThat(result.source()).isEqualTo(GenericFindingCacheManager.Source.UNAVAILABLE),
        () ->
            assertThat(result.refreshFailure())
                .hasValueSatisfying(message -> assertThat(message).contains("invalid")));
  }

  private static GenericFindingCacheEnvelope envelope(
      final GenericFindingCacheManager.CacheResult result) {
    return result.envelope().orElseThrow();
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
        List.of(VersionCoverageClaim.affected("[1.0,2.0)")),
        FieldValue.omitted(),
        FieldValue.omitted(),
        MergePriority.AUTOMATIC,
        AssessmentIntent.AUTO_VERIFY,
        provenance,
        Set.of());
  }

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
        List.of(contribution),
        List.of());
  }

  private static void writeCache(final Path cache, final GenericFindingCacheEnvelope envelope)
      throws IOException {
    Files.createDirectories(cache);
    Files.write(
        cache.resolve("index.json"), new GenericFindingCacheEnvelopeWriter().encode(envelope));
  }

  private Path initializeCveRepository(final String cveId)
      throws IOException, InterruptedException {
    final Path repository = tempDir.resolve("cve-source-" + cveId);
    Files.createDirectories(repository);
    git(repository, "init");
    git(repository, "config", "user.email", "test@example.invalid");
    git(repository, "config", "user.name", "Test");
    Files.createDirectories(repository.resolve("cves"));
    Files.writeString(repository.resolve("cves/.keep"), "checkout root\n");
    writeCveRecord(repository, cveId);
    git(repository, "add", "--all");
    git(repository, "commit", "-m", "initial CVE source");
    return repository;
  }

  private static void writeCveRecord(final Path repository, final String cveId) throws IOException {
    writeCveRecord(repository, cveId, "1.0.0");
  }

  private static void writeCveRecord(
      final Path repository, final String cveId, final String version) throws IOException {
    final Path path = recordPath(repository, cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"%s","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"library","packageURL":"pkg:maven/org.example/library",
            "versions":[{"version":"%s","status":"affected","versionType":"maven"}]}
         ]}}}
        """
            .formatted(cveId, version));
  }

  private static void writeUnmappedCveRecord(final Path repository, final String cveId)
      throws IOException {
    final Path path = recordPath(repository, cveId);
    Files.createDirectories(path.getParent());
    Files.writeString(
        path,
        """
        {"cveMetadata":{"cveId":"%s","state":"PUBLISHED"},
         "containers":{"cna":{"affected":[
           {"product":"widget","packageURL":"pkg:npm/example/widget",
            "versions":[{"version":"1.0.0","status":"affected","versionType":"npm"}]}
         ]}}}
        """
            .formatted(cveId));
  }

  private static Path recordPath(final Path repository, final String cveId) {
    return repository.resolve("cves/2026/12xxx/" + cveId + ".json");
  }

  private VulnerabilityCacheManager.CacheConfig config(
      final Path cache, final URI cveUri, final Duration ttl, final boolean forceRefresh) {
    return new VulnerabilityCacheManager.CacheConfig(
        cache,
        null,
        cveUri,
        ttl,
        forceRefresh,
        false,
        () -> new ByteArrayInputStream(new byte[0]),
        PRODUCER);
  }

  private static void git(final Path repository, final String... arguments)
      throws IOException, InterruptedException {
    final List<String> command = new java.util.ArrayList<>();
    command.add("git");
    command.add("-C");
    command.add(repository.toString());
    command.addAll(List.of(arguments));
    final Process process =
        new ProcessBuilder(command)
            .redirectErrorStream(true)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .start();
    if (!process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new IOException("Git test command timed out");
    }
    if (process.exitValue() != 0) {
      throw new IOException("Git test command failed with status " + process.exitValue());
    }
  }
}
