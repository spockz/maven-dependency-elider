/* WHY: Reconciles independent external sources into the only findings cache used downstream. */

package io.github.spockz.elider.advisory;

import io.github.spockz.elider.model.VulnerabilityFindingContribution;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/** Loads, refreshes, and publishes source-partitioned generic findings. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CyclomaticComplexity",
  "PMD.CouplingBetweenObjects"
})
// One coordinator joins storage, adapters and source refresh state.
public final class GenericFindingCacheManager {
  /** Upper bound for one Git source operation before its partition becomes stale. */
  private static final Duration GIT_TIMEOUT = Duration.ofSeconds(30);

  /** Git executable used for source checkout and revision operations. */
  private static final String GIT_COMMAND = "git";

  /** Git status indicating a removed CVE source record. */
  private static final String DELETED_STATUS = "D";

  /** Each partial observation has exactly one skipped-row summary. */
  private static final int EXPECTED_SKIPPED_SUMMARY_COUNT = 1;

  /** Carries earlier full-scan identity limitations through incremental refreshes. */
  private static final String PRIOR_UNSUPPORTED_IDENTITY_LIMITATION =
      "Prior CVE scan found unsupported Maven package identities; "
          + "incremental refresh has no complete current count";

  /** OSV cache manager, configured to ingest OSV records only. */
  private final VulnerabilityCacheManager osvCacheManager;

  /** Strict reader for the generic findings cache envelope. */
  private final GenericFindingCacheEnvelopeReader reader;

  /** Writer for the generic findings cache envelope. */
  private final GenericFindingCacheEnvelopeWriter writer;

  /** Adapter that normalizes OSV claims without alias-based CVE enrichment. */
  private final OsvVulnerabilityFindingAdapter osvAdapter;

  /** Independent CVE List v5 indexer. */
  private final CveListFindingIndexer cveIndexer;

  /** Creates the source adapters and codec used by production cache loading. */
  public GenericFindingCacheManager() {
    this(
        new VulnerabilityCacheManager(),
        new GenericFindingCacheEnvelopeReader(),
        new GenericFindingCacheEnvelopeWriter(),
        new OsvVulnerabilityFindingAdapter(),
        new CveListFindingIndexer());
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  GenericFindingCacheManager(
      final VulnerabilityCacheManager osvCacheManager,
      final GenericFindingCacheEnvelopeReader reader,
      final GenericFindingCacheEnvelopeWriter writer,
      final OsvVulnerabilityFindingAdapter osvAdapter,
      final CveListFindingIndexer cveIndexer) {
    this.osvCacheManager = Objects.requireNonNull(osvCacheManager, "osvCacheManager");
    this.reader = Objects.requireNonNull(reader, "reader");
    this.writer = Objects.requireNonNull(writer, "writer");
    this.osvAdapter = Objects.requireNonNull(osvAdapter, "osvAdapter");
    this.cveIndexer = Objects.requireNonNull(cveIndexer, "cveIndexer");
  }

  /** Loads a trusted generic cache and independently refreshes configured sources. */
  public CacheResult load(final VulnerabilityCacheManager.CacheConfig config) throws IOException {
    Objects.requireNonNull(config, "config");
    if (config.expectedProducer().isEmpty()) {
      return unavailable(
          config.producerDiagnostic().orElse("Cache producer identity is unavailable"));
    }
    final Path index = config.cacheDirectory().resolve("index.json");
    Optional<GenericFindingCacheEnvelope> cached = Optional.empty();
    Optional<String> cacheReadFailure = Optional.empty();
    try {
      cached = readCached(index, config);
    } catch (final IOException failure) {
      cacheReadFailure =
          Optional.of(
              "Generic finding cache is invalid: " + FindingJsonFields.describeFailure(failure));
    }
    final Optional<GenericFindingCacheEnvelope> cacheValue = cached;
    final Optional<String> readFailure = cacheReadFailure;
    if (config.offline()) {
      return cacheValue
          .map(value -> new CacheResult(Optional.of(value), Source.CACHE, readFailure, 0))
          .orElseGet(
              () ->
                  unavailable(readFailure.orElse("Generic findings cache is unavailable offline")));
    }

    final List<String> failures = new ArrayList<>();
    readFailure.ifPresent(failures::add);
    GenericFindingCacheEnvelope next = cacheValue.orElseGet(() -> emptyEnvelope(config));
    next = refreshOsv(config, next, failures);
    final CveRefreshResult cveRefresh = refreshCve(config, next, failures);
    next = cveRefresh.envelope();
    try {
      publish(index, next);
      return new CacheResult(
          Optional.of(next),
          Source.REFRESHED,
          failureSummary(failures),
          cveRefresh.recordsParsed());
    } catch (final IOException publicationFailure) {
      failures.add("Generic findings cache publication failed: " + publicationFailure.getMessage());
      if (cacheValue.isPresent()) {
        return new CacheResult(
            Optional.of(cacheValue.orElseThrow()),
            Source.CACHE,
            failureSummary(failures),
            cveRefresh.recordsParsed());
      }
      return unavailable(
          failureSummary(failures).orElse("Generic cache publication failed"),
          cveRefresh.recordsParsed());
    }
  }

  private GenericFindingCacheEnvelope refreshOsv(
      final VulnerabilityCacheManager.CacheConfig config,
      final GenericFindingCacheEnvelope envelope,
      final List<String> failures) {
    if (config.osvSnapshotUri() == null) {
      return envelope;
    }
    final Path sourceCache = config.cacheDirectory().resolve("osv-source");
    final VulnerabilityCacheManager.CacheConfig sourceConfig =
        new VulnerabilityCacheManager.CacheConfig(
            sourceCache,
            config.osvSnapshotUri(),
            null,
            config.ttl(),
            config.forceRefresh(),
            false,
            config.seedSupplier(),
            config.expectedProducer(),
            config.producerDiagnostic());
    try {
      final VulnerabilityCacheManager.CacheResult source = osvCacheManager.load(sourceConfig);
      final List<VulnerabilityFindingContribution> contributions =
          source.records().stream()
              .flatMap(record -> osvAdapter.contributions(record).stream())
              .toList();
      final String revision = osvRevision(source.records(), source.skippedRows());
      final Optional<String> refreshFailure = source.refreshFailure();
      if (refreshFailure.isPresent()) {
        failures.add("OSV source is stale: " + refreshFailure.orElseThrow());
        return retainOrUse(
            envelope, FindingSource.OSV, revision, contributions, refreshFailure.orElseThrow());
      }
      return envelope.withSourceSnapshot(
          new FindingSourceSnapshot(
              FindingSource.OSV,
              revision,
              Instant.now(),
              source.skippedCount() == 0
                  ? FindingSourceSnapshot.Status.CURRENT
                  : FindingSourceSnapshot.Status.PARTIAL,
              source.skippedCount() == 0
                  ? null
                  : "Skipped " + source.skippedCount() + " OSV source row(s)",
              contributions,
              source.skippedRows()));
    } catch (final IOException | IllegalArgumentException failure) {
      final String diagnostic =
          "OSV source observation failed: " + FindingJsonFields.describeFailure(failure);
      failures.add(diagnostic);
      return staleOrError(envelope, FindingSource.OSV, diagnostic);
    }
  }

  @SuppressWarnings("PMD.DoNotUseThreads")
  private CveRefreshResult refreshCve(
      final VulnerabilityCacheManager.CacheConfig config,
      final GenericFindingCacheEnvelope envelope,
      final List<String> failures) {
    if (config.cveListGitUri() == null) {
      return new CveRefreshResult(envelope, 0);
    }
    final FindingSourceSnapshot previous = envelope.sources().get(FindingSource.CVE_LIST);
    if (isFresh(previous, config)) {
      return new CveRefreshResult(envelope, 0);
    }
    final Path checkout = config.cacheDirectory().resolve("cvelistV5");
    try {
      syncCveCheckout(config.cveListGitUri(), checkout);
      final String revision = gitRevision(checkout);
      if (previous != null && revision.equals(previous.revision())) {
        return unchangedCvePartition(envelope, previous, revision);
      }
      if (previous != null && previous.revision() != null) {
        final Optional<CveRefreshResult> changed =
            refreshChangedCveRecords(envelope, checkout, previous, revision);
        if (changed.isPresent()) {
          return changed.orElseThrow();
        }
      }
      return fullCveRebuild(envelope, checkout, previous, revision);
    } catch (final InterruptedException failure) {
      Thread.currentThread().interrupt();
      return failedCveObservation(envelope, failures, failure);
    } catch (final IOException | IllegalArgumentException failure) {
      return failedCveObservation(envelope, failures, failure);
    }
  }

  private Optional<CveRefreshResult> refreshChangedCveRecords(
      final GenericFindingCacheEnvelope envelope,
      final Path checkout,
      final FindingSourceSnapshot previous,
      final String revision)
      throws IOException, InterruptedException {
    if (!canReconcileSkippedRows(previous)) {
      return Optional.empty();
    }
    final Optional<ChangedCveRecords> changed =
        changedCveRecords(checkout, previous.revision(), revision);
    if (changed.isEmpty()) {
      return Optional.empty();
    }
    final ChangedCveRecords paths = changed.orElseThrow();
    final CveListFindingIndexer.IndexResult indexed =
        cveIndexer.indexPaths(checkout, paths.presentPaths());
    final List<VulnerabilityFindingContribution> updated =
        new ArrayList<>(
            previous.contributions().stream()
                .filter(
                    contribution -> !paths.changedIds().contains(contribution.vulnerabilityId()))
                .toList());
    updated.addAll(indexed.contributions());
    final List<String> diagnostics = new ArrayList<>();
    final List<String> priorSkipped =
        previous.observationDiagnostics().stream()
            .filter(value -> value.startsWith(CveListFindingIndexer.SKIPPED_ROW_PREFIX))
            .filter(value -> !isChangedSkippedRow(value, paths.changedIds()))
            .toList();
    final List<String> newSkipped =
        indexed.observationDiagnostics().stream()
            .filter(value -> value.startsWith(CveListFindingIndexer.SKIPPED_ROW_PREFIX))
            .toList();
    final int skipped = priorSkipped.size() + indexed.skippedRows();
    indexed.observationDiagnostics().stream()
        .filter(value -> !isSkippedDiagnostic(value))
        .forEach(diagnostics::add);
    addSkippedDiagnostics(diagnostics, skipped, priorSkipped, newSkipped);
    if (hasUnsupportedIdentityDiagnostic(previous.observationDiagnostics())) {
      diagnostics.add(PRIOR_UNSUPPORTED_IDENTITY_LIMITATION);
    }
    if (paths.changedIds().isEmpty()) {
      diagnostics.add("CVE source revision changed without changed JSON records");
    }
    final FindingSourceSnapshot snapshot =
        new FindingSourceSnapshot(
            FindingSource.CVE_LIST,
            revision,
            Instant.now(),
            cveStatus(skipped),
            cveDiagnostic(skipped),
            updated,
            diagnostics);
    return Optional.of(
        new CveRefreshResult(envelope.withSourceSnapshot(snapshot), indexed.sourceRecordCount()));
  }

  private CveRefreshResult fullCveRebuild(
      final GenericFindingCacheEnvelope envelope,
      final Path checkout,
      final FindingSourceSnapshot previous,
      final String revision)
      throws IOException {
    final CveListFindingIndexer.IndexResult indexed = cveIndexer.index(checkout);
    final List<String> diagnostics = new ArrayList<>(indexed.observationDiagnostics());
    if (previous != null && previous.revision() != null) {
      diagnostics.add("CVE changed-path diff unavailable; full source rebuild completed");
    }
    final FindingSourceSnapshot snapshot =
        new FindingSourceSnapshot(
            FindingSource.CVE_LIST,
            revision,
            Instant.now(),
            cveStatus(indexed.skippedRows()),
            cveDiagnostic(indexed.skippedRows()),
            indexed.contributions(),
            diagnostics);
    return new CveRefreshResult(envelope.withSourceSnapshot(snapshot), indexed.sourceRecordCount());
  }

  private static CveRefreshResult unchangedCvePartition(
      final GenericFindingCacheEnvelope envelope,
      final FindingSourceSnapshot previous,
      final String revision) {
    final List<String> diagnostics = new ArrayList<>(previous.observationDiagnostics());
    final String unchangedDiagnostic = "CVE source revision unchanged; no records parsed";
    if (!diagnostics.contains(unchangedDiagnostic)) {
      diagnostics.add(unchangedDiagnostic);
    }
    final boolean partial =
        previous.status() == FindingSourceSnapshot.Status.PARTIAL
            || diagnostics.stream()
                .anyMatch(value -> value.startsWith(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX));
    final FindingSourceSnapshot snapshot =
        new FindingSourceSnapshot(
            FindingSource.CVE_LIST,
            revision,
            Instant.now(),
            partial ? FindingSourceSnapshot.Status.PARTIAL : FindingSourceSnapshot.Status.CURRENT,
            partial ? partialDiagnostic(diagnostics) : null,
            previous.contributions(),
            diagnostics);
    return new CveRefreshResult(envelope.withSourceSnapshot(snapshot), 0);
  }

  private static FindingSourceSnapshot.Status cveStatus(final int skipped) {
    return skipped == 0
        ? FindingSourceSnapshot.Status.CURRENT
        : FindingSourceSnapshot.Status.PARTIAL;
  }

  private static String cveDiagnostic(final int skipped) {
    return skipped == 0 ? null : "CVE List index is incomplete: skipped " + skipped + " rows";
  }

  private static String partialDiagnostic(final List<String> diagnostics) {
    return diagnostics.stream()
        .filter(value -> value.startsWith(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX))
        .findFirst()
        .orElse("CVE List index is incomplete; skipped-row details are unavailable");
  }

  private static boolean canReconcileSkippedRows(final FindingSourceSnapshot previous) {
    final List<String> diagnostics = previous.observationDiagnostics();
    if (diagnostics.stream()
        .anyMatch(value -> value.startsWith(CveListFindingIndexer.SKIPPED_OVERFLOW_PREFIX))) {
      return false;
    }
    final List<String> summaries =
        diagnostics.stream()
            .filter(value -> value.startsWith(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX))
            .toList();
    final List<String> details =
        diagnostics.stream()
            .filter(value -> value.startsWith(CveListFindingIndexer.SKIPPED_ROW_PREFIX))
            .toList();
    if (summaries.isEmpty()) {
      return previous.status() != FindingSourceSnapshot.Status.PARTIAL && details.isEmpty();
    }
    if (summaries.size() != EXPECTED_SKIPPED_SUMMARY_COUNT) {
      return false;
    }
    final String countAndDescription =
        summaries.getFirst().substring(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX.length());
    final int separator = countAndDescription.indexOf(' ');
    if (separator <= 0 || separator > 9) {
      return false;
    }
    final String count = countAndDescription.substring(0, separator);
    if (!count.chars().allMatch(Character::isDigit)) {
      return false;
    }
    return Integer.parseInt(count) == details.size()
        && details.stream().allMatch(GenericFindingCacheManager::hasCanonicalSkippedRowId);
  }

  private static boolean hasCanonicalSkippedRowId(final String diagnostic) {
    final String remainder =
        diagnostic.substring(CveListFindingIndexer.SKIPPED_ROW_PREFIX.length());
    final int separator = remainder.indexOf(':');
    return separator > 0 && remainder.substring(0, separator).matches("CVE-[0-9]{4}-[0-9]{4,}");
  }

  private static boolean isChangedSkippedRow(final String diagnostic, final Set<String> changed) {
    final String remainder =
        diagnostic.substring(CveListFindingIndexer.SKIPPED_ROW_PREFIX.length());
    return changed.contains(remainder.substring(0, remainder.indexOf(':')));
  }

  private static boolean isSkippedDiagnostic(final String diagnostic) {
    return diagnostic.startsWith(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX)
        || diagnostic.startsWith(CveListFindingIndexer.SKIPPED_ROW_PREFIX)
        || diagnostic.startsWith(CveListFindingIndexer.SKIPPED_OVERFLOW_PREFIX);
  }

  private static void addSkippedDiagnostics(
      final List<String> diagnostics,
      final int skipped,
      final List<String> priorSkipped,
      final List<String> newSkipped) {
    if (skipped == 0) {
      return;
    }
    diagnostics.add(CveListFindingIndexer.SKIPPED_SUMMARY_PREFIX + skipped + " malformed rows");
    java.util.stream.Stream.concat(priorSkipped.stream(), newSkipped.stream())
        .limit(CveListFindingIndexer.MAX_SKIPPED_ROW_DIAGNOSTICS)
        .forEach(diagnostics::add);
    if (skipped > CveListFindingIndexer.MAX_SKIPPED_ROW_DIAGNOSTICS) {
      diagnostics.add(
          CveListFindingIndexer.SKIPPED_OVERFLOW_PREFIX
              + " after "
              + CveListFindingIndexer.MAX_SKIPPED_ROW_DIAGNOSTICS);
    }
  }

  private static boolean hasUnsupportedIdentityDiagnostic(final List<String> diagnostics) {
    return diagnostics.stream()
        .anyMatch(
            value ->
                value.contains("lacked a supported Maven package identity")
                    || PRIOR_UNSUPPORTED_IDENTITY_LIMITATION.equals(value));
  }

  private CveRefreshResult failedCveObservation(
      final GenericFindingCacheEnvelope envelope,
      final List<String> failures,
      final Exception failure) {
    final String diagnostic =
        "CVE List source observation failed: " + FindingJsonFields.describeFailure(failure);
    failures.add(diagnostic);
    return new CveRefreshResult(staleOrError(envelope, FindingSource.CVE_LIST, diagnostic), 0);
  }

  private static Optional<ChangedCveRecords> changedCveRecords(
      final Path checkout, final String before, final String after)
      throws IOException, InterruptedException {
    final GitCommandResult command =
        captureGitOutput(
            new ProcessBuilder(
                GIT_COMMAND,
                "-C",
                checkout.toString(),
                "diff",
                "--name-status",
                "-z",
                "--no-renames",
                before,
                after,
                "--",
                "cves/"),
            GIT_TIMEOUT);
    if (!command.completed() || command.exitCode() != 0) {
      return Optional.empty();
    }
    final String[] fields = new String(command.output(), StandardCharsets.UTF_8).split("\u0000");
    return parseChangedCveRecords(checkout, fields);
  }

  private static Optional<ChangedCveRecords> parseChangedCveRecords(
      final Path checkout, final String... fields) {
    final Set<String> changedIds = new TreeSet<>();
    final Set<Path> presentPaths = new TreeSet<>();
    int index = 0;
    while (index < fields.length && !fields[index].isEmpty()) {
      final String status = fields[index];
      if (index + 1 >= fields.length || !isSupportedChangeStatus(status)) {
        return Optional.empty();
      }
      final Optional<ParsedCvePath> parsed = parseCvePath(checkout, status, fields[index + 1]);
      index += 2;
      if (parsed.isEmpty()) {
        return Optional.empty();
      }
      final ParsedCvePath cvePath = parsed.orElseThrow();
      if (cvePath.cveId() != null) {
        changedIds.add(cvePath.cveId());
      }
      if (cvePath.presentPath() != null) {
        presentPaths.add(cvePath.presentPath());
      }
    }
    return Optional.of(new ChangedCveRecords(changedIds, List.copyOf(presentPaths)));
  }

  private static Optional<ParsedCvePath> parseCvePath(
      final Path checkout, final String status, final String rawPath) {
    final Path path;
    try {
      path = Path.of(rawPath);
    } catch (final java.nio.file.InvalidPathException invalidPath) {
      return Optional.empty();
    }
    final Path filename = path.getFileName();
    if (filename == null) {
      return Optional.empty();
    }
    if (path.getNameCount() == 2
        && "cves".equals(path.getName(0).toString())
        && ("delta.json".equals(filename.toString())
            || "deltaLog.json".equals(filename.toString()))) {
      return Optional.of(new ParsedCvePath(null, null));
    }
    if (!filename.toString().endsWith(".json")) {
      return Optional.of(new ParsedCvePath(null, null));
    }
    final String cveId;
    try {
      cveId = CveListFindingIndexer.canonicalCveId(path);
    } catch (final IOException malformedPath) {
      return Optional.empty();
    }
    if (DELETED_STATUS.equals(status)) {
      return Optional.of(new ParsedCvePath(cveId, null));
    }
    final Path current = checkout.resolve(path).normalize();
    if (!current.startsWith(checkout) || !Files.isRegularFile(current)) {
      return Optional.empty();
    }
    return Optional.of(new ParsedCvePath(cveId, path));
  }

  private static boolean isSupportedChangeStatus(final String status) {
    return "A".equals(status) || "M".equals(status) || "D".equals(status);
  }

  private static boolean isFresh(
      final FindingSourceSnapshot snapshot, final VulnerabilityCacheManager.CacheConfig config) {
    return snapshot != null
        && (snapshot.status() == FindingSourceSnapshot.Status.CURRENT
            || snapshot.status() == FindingSourceSnapshot.Status.PARTIAL)
        && !config.forceRefresh()
        && Duration.between(snapshot.lastSuccessfulSync(), Instant.now()).compareTo(config.ttl())
            < 0;
  }

  private static GenericFindingCacheEnvelope retainOrUse(
      final GenericFindingCacheEnvelope envelope,
      final FindingSource source,
      final String revision,
      final List<VulnerabilityFindingContribution> currentContributions,
      final String diagnostic) {
    if (envelope.sources().containsKey(source)) {
      return staleOrError(envelope, source, diagnostic);
    }
    return envelope.withSourceSnapshot(
        new FindingSourceSnapshot(
            source,
            revision,
            Instant.now(),
            FindingSourceSnapshot.Status.STALE,
            diagnostic,
            currentContributions,
            List.of()));
  }

  private static GenericFindingCacheEnvelope staleOrError(
      final GenericFindingCacheEnvelope envelope,
      final FindingSource source,
      final String diagnostic) {
    final FindingSourceSnapshot previous = envelope.sources().get(source);
    final FindingSourceSnapshot failed =
        previous == null
            ? new FindingSourceSnapshot(
                source,
                null,
                null,
                FindingSourceSnapshot.Status.ERROR,
                diagnostic,
                List.of(),
                List.of())
            : new FindingSourceSnapshot(
                source,
                previous.revision(),
                previous.lastSuccessfulSync(),
                FindingSourceSnapshot.Status.STALE,
                diagnostic,
                previous.contributions(),
                previous.observationDiagnostics());
    return envelope.withSourceSnapshot(failed);
  }

  private Optional<GenericFindingCacheEnvelope> readCached(
      final Path index, final VulnerabilityCacheManager.CacheConfig config) throws IOException {
    if (!Files.isRegularFile(index)) {
      return Optional.empty();
    }
    try (InputStream input = Files.newInputStream(index)) {
      return Optional.of(reader.read(input, config.expectedProducer().orElseThrow()));
    } catch (final IOException | IllegalArgumentException failure) {
      throw new IOException(
          "Could not read generic finding cache: " + FindingJsonFields.describeFailure(failure),
          failure);
    }
  }

  private GenericFindingCacheEnvelope emptyEnvelope(
      final VulnerabilityCacheManager.CacheConfig config) {
    return new GenericFindingCacheEnvelope(
        config.expectedProducer().orElseThrow(), java.util.Map.of());
  }

  private static CacheResult unavailable(final String diagnostic) {
    return unavailable(diagnostic, 0);
  }

  private static CacheResult unavailable(final String diagnostic, final int cveRecordsParsed) {
    return new CacheResult(
        Optional.empty(), Source.UNAVAILABLE, Optional.of(diagnostic), cveRecordsParsed);
  }

  private void publish(final Path index, final GenericFindingCacheEnvelope envelope)
      throws IOException {
    Files.createDirectories(Objects.requireNonNull(index.toAbsolutePath().getParent()));
    final Path staged = index.resolveSibling("index.json.tmp");
    try {
      Files.write(staged, writer.encode(envelope));
      VulnerabilityCacheManager.replaceWithFallback(staged, index);
    } finally {
      Files.deleteIfExists(staged);
    }
  }

  private static void syncCveCheckout(final URI uri, final Path checkout)
      throws IOException, InterruptedException {
    VulnerabilityCacheManager.syncGitOrThrow(uri, checkout, GIT_TIMEOUT);
  }

  private static String gitRevision(final Path checkout) throws IOException, InterruptedException {
    final GitCommandResult command =
        captureGitOutput(
            new ProcessBuilder(GIT_COMMAND, "-C", checkout.toString(), "rev-parse", "HEAD"),
            GIT_TIMEOUT);
    if (!command.completed()) {
      throw new IOException("Git revision lookup timed out");
    }
    if (command.exitCode() != 0) {
      throw new IOException(
          "Git revision lookup failed: " + new String(command.output(), StandardCharsets.UTF_8));
    }
    final String revision = new String(command.output(), StandardCharsets.UTF_8).trim();
    if (!revision.matches("[0-9a-fA-F]{40,64}")) {
      throw new IOException("Git returned a malformed source revision");
    }
    return revision.toLowerCase(java.util.Locale.ROOT);
  }

  /** Captures process output without blocking the timeout on a full or open pipe. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static GitCommandResult captureGitOutput(final ProcessBuilder command, final Duration timeout)
      throws IOException, InterruptedException {
    final Path output = Files.createTempFile("elider-git-output-", ".tmp");
    try {
      command.redirectOutput(output.toFile());
      command.redirectError(ProcessBuilder.Redirect.DISCARD);
      final Process process = command.start();
      try {
        if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
          process.destroyForcibly();
          final boolean stopped = process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS);
          return new GitCommandResult(false, !stopped, -1, new byte[0]);
        }
      } catch (final InterruptedException interrupted) {
        process.destroyForcibly();
        throw interrupted;
      }
      return new GitCommandResult(true, false, process.exitValue(), Files.readAllBytes(output));
    } finally {
      Files.deleteIfExists(output);
    }
  }

  /** Immutable result of one timed Git process with captured standard output. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record GitCommandResult(boolean completed, boolean processAlive, int exitCode, byte[] output) {
    GitCommandResult {
      output = output.clone();
    }

    @Override
    public byte[] output() {
      return output.clone();
    }
  }

  private static String osvRevision(
      final List<io.github.spockz.elider.model.OsvAdvisoryRecord> records,
      final List<String> skippedRows)
      throws IOException {
    final List<String> identities =
        records.stream().map(record -> record.osvId() + "\t" + record.modified()).sorted().toList();
    final MessageDigest digest = io.github.spockz.elider.model.ArtifactDigests.newSha256Digest();
    identities.forEach(value -> digest.update((value + "\n").getBytes(StandardCharsets.UTF_8)));
    skippedRows.stream()
        .sorted()
        .forEach(
            value -> digest.update(("skipped:" + value + "\n").getBytes(StandardCharsets.UTF_8)));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static Optional<String> failureSummary(final List<String> failures) {
    return failures.isEmpty()
        ? Optional.empty()
        : Optional.of(failures.stream().collect(Collectors.joining("; ")));
  }

  /** Cache outcome consumed by assessment; it exposes only normalized contributions. */
  public record CacheResult(
      Optional<GenericFindingCacheEnvelope> envelope,
      Source source,
      Optional<String> refreshFailure,
      int cveRecordsParsed) {
    /** Validates cache state and the number of records parsed during refresh. */
    public CacheResult {
      Objects.requireNonNull(envelope, "envelope");
      Objects.requireNonNull(source, "source");
      Objects.requireNonNull(refreshFailure, "refreshFailure");
      if (cveRecordsParsed < 0) {
        throw new IllegalArgumentException("cveRecordsParsed must not be negative");
      }
    }

    /** Returns trusted source contributions, or none when the cache is unavailable. */
    public List<VulnerabilityFindingContribution> contributions() {
      return envelope.map(GenericFindingCacheEnvelope::contributions).orElseGet(List::of);
    }
  }

  /** Identifies trusted cache replay, refreshed data, or unavailable cache state. */
  public enum Source {
    CACHE,
    REFRESHED,
    UNAVAILABLE
  }

  private record CveRefreshResult(GenericFindingCacheEnvelope envelope, int recordsParsed) {
    private CveRefreshResult {
      Objects.requireNonNull(envelope, "envelope");
      if (recordsParsed < 0) {
        throw new IllegalArgumentException("recordsParsed must not be negative");
      }
    }
  }

  private record ChangedCveRecords(Set<String> changedIds, List<Path> presentPaths) {
    private ChangedCveRecords {
      changedIds = Set.copyOf(changedIds);
      presentPaths = List.copyOf(presentPaths);
    }
  }

  private record ParsedCvePath(String cveId, Path presentPath) {}
}
