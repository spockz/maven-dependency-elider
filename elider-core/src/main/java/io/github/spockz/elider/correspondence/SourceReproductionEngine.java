// WHY: Reproduces source archives in core without accepting plugin approval or Maven resolver
// types.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;

/** Reproduces one exact source archive using the core's pinned compiler identity. */
public final class SourceReproductionEngine {
  /** Stable diagnostic label for the original artifact. */
  private static final String ORIGINAL_LABEL = "original";

  /** Stable diagnostic label for the sources artifact. */
  private static final String SOURCES_LABEL = "sources";

  /** Compiler image is captured once for the enclosing assessment invocation. */
  private final SourceJdkIdentity.Resolution compilerIdentity;

  /** Owns keyed metadata until the assessment makes its final proof decision. */
  private final SourceReproductionInvocationCache invocationCache =
      new SourceReproductionInvocationCache();

  private SourceReproductionEngine(final SourceJdkIdentity.Resolution compilerIdentity) {
    this.compilerIdentity = compilerIdentity;
  }

  /** Captures the running compiler and platform against the fixed supported image. */
  public static SourceReproductionEngine forCurrentJdk() {
    return new SourceReproductionEngine(SourceJdkIdentity.current());
  }

  /** Reproduces or returns a diagnosed non-authoritative abstention. */
  public SourceReproductionResult reproduce(final SourceReproductionRequest request) {
    if (compilerIdentity.identity().isEmpty()) {
      return new SourceReproductionResult.Abstained(compilerIdentity.refusal().orElseThrow());
    }
    try {
      return reproduceStrict(request, compilerIdentity.identity().orElseThrow());
    } catch (final IOException | IllegalArgumentException failure) {
      return new SourceReproductionResult.Abstained(reason(failure));
    }
  }

  /** Returns invocation counts for archive and compiler work. */
  public InvocationDiagnostics diagnostics() {
    final SourceReproductionInvocationCache.Snapshot snapshot = invocationCache.snapshot();
    return new InvocationDiagnostics(
        snapshot.originalArchiveParses(),
        snapshot.sourceArchiveParses(),
        snapshot.compilerInvocations(),
        snapshot.reproductionCacheHits(),
        snapshot.physicalInventoryParses(),
        snapshot.physicalInventoryCacheHits(),
        snapshot.physicalInventoryReusesFromReproduction());
  }

  /** Reads or reuses a current physical inventory. */
  public Set<String> readPhysicalClassInventory(
      final ArtifactCoordinate coordinate, final Path path, final String expectedSha256)
      throws IOException {
    return invocationCache.readPhysicalClassInventory(coordinate, path, expectedSha256);
  }

  private SourceReproductionResult.Completed reproduceStrict(
      final SourceReproductionRequest request, final SourceJdkIdentity.Identity compilerIdentity)
      throws IOException {
    final SourceReproductionRequestValidator.ValidatedPaths paths =
        SourceReproductionRequestValidator.validate(request);
    final Path originalPath = paths.original();
    final Path sourcePath = paths.sources();
    final String originalSha256 = SourceFileDigest.sha256(originalPath);
    final String sourceSha256 = SourceFileDigest.sha256(sourcePath);
    final SourceReproductionInvocationCache.ReproductionKey key =
        new SourceReproductionInvocationCache.ReproductionKey(
            request.candidate().toId(),
            request.sourcesCoordinate().toId(),
            originalPath,
            sourcePath,
            originalSha256,
            sourceSha256,
            request.sourceRepositoryProvenance(),
            request.conventionalLayoutAssumed(),
            compilerIdentity.toString(),
            SourceUnitCompiler.fixedOptions());
    final java.util.Optional<SourceReproductionInvocationCache.PreparedReproduction> cached =
        invocationCache.reproduction(key);
    final SourceReproductionInvocationCache.PreparedReproduction prepared;
    if (cached.isEmpty()) {
      prepared =
          prepareReproduction(
              request, originalPath, sourcePath, compilerIdentity, originalSha256, sourceSha256);
      invocationCache.cacheReproduction(
          key, prepared, request.candidate(), originalPath, originalSha256);
    } else {
      invocationCache.recordReproductionHit();
      prepared = cached.orElseThrow();
    }
    SourceReproductionRequestValidator.requireClaimPresence(
        request.sourceClaims(), request.routineClaims(), prepared.sourceEntries());
    final Map<String, String> mappedFiles =
        SourceCorrespondencePathMapper.map(
            request.sourceClaims(), prepared.sourceEntries(), request.conventionalLayoutAssumed());
    SourceCorrespondenceAdmission.requireUniqueRoutineOwners(
        prepared.compilation().units(), request.routineClaims());
    SourceReproductionRequestValidator.requireStableArchive(
        ORIGINAL_LABEL, originalSha256, SourceFileDigest.sha256(originalPath));
    SourceReproductionRequestValidator.requireStableArchive(
        SOURCES_LABEL, sourceSha256, SourceFileDigest.sha256(sourcePath));
    return new SourceReproductionResult.Completed(
        request.candidate(),
        request.sourcesCoordinate(),
        request.sourceRepositoryProvenance(),
        originalSha256,
        sourceSha256,
        prepared.compilation().compilerIdentity(),
        prepared.compilation().options(),
        prepared.originalClasses(),
        prepared.compilation().units(),
        mappedFiles);
  }

  private SourceReproductionInvocationCache.PreparedReproduction prepareReproduction(
      final SourceReproductionRequest request,
      final Path originalPath,
      final Path sourcePath,
      final SourceJdkIdentity.Identity compilerIdentity,
      final String expectedOriginalSha256,
      final String expectedSourceSha256)
      throws IOException {
    final SourceCorrespondenceArchive original =
        readArchive(originalPath, expectedOriginalSha256, false);
    final SourceCorrespondenceArchive sources = readArchive(sourcePath, expectedSourceSha256, true);
    SourceReproductionRequestValidator.requireStableArchive(
        ORIGINAL_LABEL, expectedOriginalSha256, original.sha256());
    SourceReproductionRequestValidator.requireStableArchive(
        SOURCES_LABEL, expectedSourceSha256, sources.sha256());
    SourceReproductionRequestValidator.requireClaimPresence(
        request.sourceClaims(), request.routineClaims(), sources.sourceEntries());
    final SourceUnitCompiler.Compilation compilation =
        SourceUnitCompiler.compile(
            sources, originalPath, compilerIdentity, invocationCache::compilerTaskStarted);
    SourceUnitIdentityValidator.requireUnique(compilation.units());
    SourceCorrespondenceAdmission.requireInventoryMatch(original.classes(), compilation.units());
    SourceReproductionRequestValidator.requireStableArchive(
        ORIGINAL_LABEL, expectedOriginalSha256, SourceFileDigest.sha256(originalPath));
    SourceReproductionRequestValidator.requireStableArchive(
        SOURCES_LABEL, expectedSourceSha256, SourceFileDigest.sha256(sourcePath));
    return new SourceReproductionInvocationCache.PreparedReproduction(
        sources.sourceEntries(), original.classes(), compilation);
  }

  private SourceCorrespondenceArchive readArchive(
      final Path path, final String sha256, final boolean sources) throws IOException {
    final SourceCorrespondenceArchive parsed;
    invocationCache.archiveParsed(sources);
    if (sources) {
      parsed = SourceCorrespondenceArchiveReader.readSources(path);
    } else {
      parsed = SourceCorrespondenceArchiveReader.readOriginal(path);
    }
    SourceReproductionRequestValidator.requireStableArchive(
        sources ? SOURCES_LABEL : ORIGINAL_LABEL, sha256, parsed.sha256());
    return parsed;
  }

  /** Releases candidate-local metadata after their final proof decision. */
  public void releaseCandidates(final java.util.Collection<ArtifactCoordinate> candidates) {
    invocationCache.releaseCandidates(candidates);
  }

  /** Immutable counts of parsing, compilation, and cache hits. */
  public record InvocationDiagnostics(
      long originalArchiveParses,
      long sourceArchiveParses,
      long compilerInvocations,
      long reproductionCacheHits,
      long physicalInventoryParses,
      long physicalInventoryCacheHits,
      long physicalInventoryReusesFromReproduction) {}

  private static String reason(final Exception failure) {
    final String message = failure.getMessage();
    return message == null || message.isBlank() ? "Source reproduction failed" : message;
  }
}
