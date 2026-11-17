/* WHY: Performs zero-resolution config and path checks in Maven's validate phase. */

package io.github.spockz.elider.plugin;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.MojoFailureException;

/** Lightweight configuration and path checks for Maven's {@code validate} phase. */
final class MavenElideConfigurationValidation {
  private MavenElideConfigurationValidation() {
    throw new AssertionError("No instances");
  }

  /* default */ static void validate(final Request request) throws MojoFailureException {
    try {
      validateFlags(request);
      validateTrimSettings(request);
      validateCoordinates(request);
      validateAdvisorySettings(request);
      validateTraceFiles(request.traceFiles());
      validateCacheDirectory(request.cveCacheDirectory());
      validateOutputTargets(request);
    } catch (final IOException | IllegalArgumentException exception) {
      throw new MojoFailureException(
          "Dependency elision configuration validation failed: " + exception.getMessage(),
          exception);
    }
  }

  private static void validateFlags(final Request request) {
    if (request.sourceRootsComplete()) {
      throw new IllegalArgumentException(
          "elide.sourceRootsComplete is no longer supported; bind elide to process-classes");
    }
  }

  private static void validateTrimSettings(final Request request) {
    if (request.trimWorkers() < MavenDependencyTrimmer.MIN_TRIM_WORKERS) {
      throw new IllegalArgumentException("trimWorkers must be at least 1");
    }
    MrjarStrategy.parse(request.mrjarStrategy());
    new DuplicateClassPolicy(
        request.retainDuplicateClassOwners(), request.trimDuplicateClassOwners());
    if (request.trimRoots() != null) {
      for (final String root : request.trimRoots()) {
        if (root == null || root.isBlank()) {
          throw new IllegalArgumentException("elide.trimRoots must not contain blank entries");
        }
      }
    }
  }

  private static void validateCoordinates(final Request request) throws MojoFailureException {
    ElisionArtifactPolicy.parseRetentionCoordinates(request.retainedArtifacts());
    if (request.trimSkipArtifacts() != null) {
      for (final String skipArtifact : request.trimSkipArtifacts()) {
        MavenArtifactIdentity.parsePassThrough(skipArtifact);
      }
    }
    BanishedDependencyPolicy.normalize(request.banishedDependencies());
    if (request.vulnerabilityMappingCatalogs() != null) {
      for (final String catalog : request.vulnerabilityMappingCatalogs()) {
        MavenVulnerabilityMappingCatalogResolver.Coordinate.parse(catalog);
      }
    }
  }

  private static void validateAdvisorySettings(final Request request) {
    if (request.cveCacheTtlHours() < 0) {
      throw new IllegalArgumentException("elide.cveCacheTtlHours must not be negative");
    }
    validateOptionalUri("elide.osvSnapshotUri", request.osvSnapshotUri());
    validateOptionalUri("elide.cveListGitUri", request.cveListGitUri());
    if (request.snykApiBaseUri() != null && !request.snykApiBaseUri().isBlank()) {
      SnykPackageIssuesIntegration.validateApiBaseUri(request.snykApiBaseUri());
    }
    ConfiguredVulnerabilityMappings.fromPom(request.vulnerabilityMappings());
  }

  private static void validateOptionalUri(final String property, final String rawUri) {
    if (rawUri == null || rawUri.isBlank()) {
      return;
    }
    try {
      URI.create(rawUri.trim());
    } catch (final IllegalArgumentException exception) {
      throw new IllegalArgumentException("Invalid " + property + " URI: " + rawUri, exception);
    }
  }

  private static void validateTraceFiles(final List<File> traceFiles) {
    if (traceFiles == null) {
      return;
    }
    for (final File traceFile : traceFiles) {
      if (traceFile == null) {
        throw new IllegalArgumentException("elide.traceFiles must not contain null entries");
      }
      final Path path = traceFile.toPath();
      if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
        throw new IllegalArgumentException(
            "elide.traceFiles entry must be an existing readable file: " + path);
      }
    }
  }

  private static void validateCacheDirectory(final File cveCacheDirectory) {
    if (cveCacheDirectory == null) {
      return;
    }
    final Path cachePath = cveCacheDirectory.toPath();
    if (Files.exists(cachePath) && !Files.isDirectory(cachePath)) {
      throw new IllegalArgumentException(
          "elide.cveCacheDirectory must be a directory: " + cachePath);
    }
  }

  private static void validateOutputTargets(final Request request) throws IOException {
    final List<Path> outputs = new ArrayList<>();
    for (final File file :
        new File[] {
          request.reportFile(),
          request.sbomFile(),
          request.baselineSbomFile(),
          request.vexFile(),
          request.summaryFile()
        }) {
      if (file != null) {
        outputs.add(file.toPath());
      }
    }
    if (!outputs.isEmpty()) {
      MavenOutputTargetValidation.validate(outputs);
    }
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record Request(
      boolean sourceRootsComplete,
      int trimWorkers,
      String mrjarStrategy,
      List<String> retainDuplicateClassOwners,
      List<String> trimDuplicateClassOwners,
      List<String> trimRoots,
      List<String> retainedArtifacts,
      List<String> trimSkipArtifacts,
      List<String> banishedDependencies,
      List<String> vulnerabilityMappingCatalogs,
      int cveCacheTtlHours,
      String osvSnapshotUri,
      String cveListGitUri,
      String snykApiBaseUri,
      List<VulnerabilityMappingConfig> vulnerabilityMappings,
      List<File> traceFiles,
      File cveCacheDirectory,
      File reportFile,
      File sbomFile,
      File baselineSbomFile,
      File vexFile,
      File summaryFile) {}
}
