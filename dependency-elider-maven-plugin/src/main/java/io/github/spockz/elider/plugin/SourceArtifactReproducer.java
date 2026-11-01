// WHY: Coordinates validated archive inputs, claim mapping, and exact isolated recompilation.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Reproduces an exact artifact from its Maven sources archive. */
final class SourceArtifactReproducer {
  /** JAR extension allowed by the initial non-transformed Java source path. */
  private static final String JAR_TYPE = "jar";

  /** Maven classifier resolved for source/build correspondence. */
  private static final String SOURCES_CLASSIFIER = "sources";

  private SourceArtifactReproducer() {}

  /* default */ static Outcome reproduce(
      final ArtifactCoordinate candidate,
      final MavenSourceClassifierResolver.ResolvedSourceArtifact resolvedSources,
      final Path originalJar,
      final List<String> sourceClaims,
      final List<String> routineClaims,
      final boolean conventionalLayoutAssumed,
      final SourceJdkIdentity.Identity compilerIdentity) {
    try {
      return reproduceStrict(
          candidate,
          resolvedSources,
          originalJar,
          sourceClaims,
          routineClaims,
          conventionalLayoutAssumed,
          compilerIdentity);
    } catch (final IOException | IllegalArgumentException failure) {
      return new Abstained(reason(failure));
    }
  }

  private static Outcome reproduceStrict(
      final ArtifactCoordinate candidate,
      final MavenSourceClassifierResolver.ResolvedSourceArtifact resolvedSources,
      final Path originalJar,
      final List<String> sourceClaims,
      final List<String> routineClaims,
      final boolean conventionalLayoutAssumed,
      final SourceJdkIdentity.Identity compilerIdentity)
      throws IOException {
    validateCoordinates(candidate, resolvedSources);
    final Path originalPath = requireJar(originalJar, "original artifact");
    final Path sourcePath = requireJar(resolvedSources.path(), "sources artifact");
    final String originalSha256 = ArtifactFileDigest.sha256(originalPath);
    final String sourceSha256 = ArtifactFileDigest.sha256(sourcePath);
    final SourceCorrespondenceArchive original =
        SourceCorrespondenceArchiveReader.readOriginal(originalPath);
    final SourceCorrespondenceArchive sources =
        SourceCorrespondenceArchiveReader.readSources(sourcePath);
    requireStableArchive("original", originalSha256, original.sha256());
    requireStableArchive("sources", sourceSha256, sources.sha256());
    final Map<String, String> mappedFiles =
        SourceCorrespondencePathMapper.map(
            sourceClaims, sources.sourceEntries(), conventionalLayoutAssumed);
    requireClaimPresence(sourceClaims, routineClaims, sources);
    final SourceUnitCompiler.Compilation compilation =
        SourceUnitCompiler.compile(sources, originalPath, compilerIdentity);
    SourceCorrespondenceAdmission.requireUniqueRoutineOwners(compilation.units(), routineClaims);
    SourceCorrespondenceAdmission.requireInventoryMatch(original.classes(), compilation.units());
    requireStableArchive("original", originalSha256, ArtifactFileDigest.sha256(originalPath));
    requireStableArchive("sources", sourceSha256, ArtifactFileDigest.sha256(sourcePath));
    return new Reproduced(
        candidate,
        resolvedSources.coordinate(),
        resolvedSources.repositoryProvenance(),
        originalSha256,
        sourceSha256,
        compilation.compilerIdentity(),
        compilation.options(),
        original.classes(),
        compilation.units(),
        mappedFiles);
  }

  private static void validateCoordinates(
      final ArtifactCoordinate candidate,
      final MavenSourceClassifierResolver.ResolvedSourceArtifact sources)
      throws IOException {
    if (candidate == null || sources == null || candidate.version() == null) {
      throw new IOException("Exact candidate and sources coordinates are required");
    }
    final ArtifactCoordinate sourceCoordinate = sources.coordinate();
    validateOriginalKind(candidate);
    validateSourcesKind(candidate, sourceCoordinate);
  }

  private static void validateOriginalKind(final ArtifactCoordinate candidate) throws IOException {
    if (!JAR_TYPE.equals(candidate.type()) || !candidate.classifier().isEmpty()) {
      throw new IOException("Only ordinary unclassified JAR artifacts are supported");
    }
  }

  private static void validateSourcesKind(
      final ArtifactCoordinate candidate, final ArtifactCoordinate sourceCoordinate)
      throws IOException {
    final boolean matches =
        candidate.groupId().equals(sourceCoordinate.groupId())
            && candidate.artifactId().equals(sourceCoordinate.artifactId())
            && candidate.version().equals(sourceCoordinate.version())
            && JAR_TYPE.equals(sourceCoordinate.type())
            && SOURCES_CLASSIFIER.equals(sourceCoordinate.classifier());
    if (!matches) {
      throw new IOException("Sources artifact does not match the exact candidate GAVCE");
    }
  }

  private static Path requireJar(final Path path, final String label) throws IOException {
    if (path == null) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    final Path fileName = path.getFileName();
    if (!Files.isRegularFile(path) || fileName == null) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    if (!fileName.toString().endsWith(".jar")) {
      throw invalidArtifact(label, "must be a regular JAR file");
    }
    return path.toAbsolutePath().normalize();
  }

  private static void requireClaimPresence(
      final List<String> files,
      final List<String> routines,
      final SourceCorrespondenceArchive sources)
      throws IOException {
    if (isEmpty(files) && isEmpty(routines)) {
      throw new IOException("At least one structured source or routine claim is required");
    }
    if (sources.sourceEntries().isEmpty()) {
      throw new IOException("Sources archive contains no Java source units");
    }
  }

  private static boolean isEmpty(final List<String> values) {
    return values == null || values.isEmpty();
  }

  private static void requireStableArchive(
      final String label, final String expected, final String actual) throws IOException {
    if (!expected.equals(actual)) {
      throw invalidArtifact(label, "artifact changed during source reproduction");
    }
  }

  private static IOException invalidArtifact(final String label, final String reason) {
    return new IOException("The " + label + " " + reason);
  }

  private static String reason(final Exception failure) {
    final String message = failure.getMessage();
    return message == null || message.isBlank() ? "Source reproduction failed" : message;
  }

  /** Non-authoritative outcome of source correspondence. */
  /* default */ sealed interface Outcome permits Reproduced, Abstained {}

  /** Correspondence retained for later live-validation work. */
  /* default */ record Reproduced(
      ArtifactCoordinate candidate,
      ArtifactCoordinate sourcesCoordinate,
      String sourceRepositoryProvenance,
      String originalArchiveSha256,
      String sourcesArchiveSha256,
      String compilerIdentity,
      List<String> compilerOptions,
      List<SourceBuildCorrespondence.ClassEntry> originalClassInventory,
      List<SourceBuildCorrespondence.SourceUnit> sourceUnits,
      Map<String, String> mappedClaims)
      implements Outcome {
    /* default */ Reproduced {
      compilerOptions = List.copyOf(compilerOptions);
      originalClassInventory = List.copyOf(originalClassInventory);
      sourceUnits = List.copyOf(sourceUnits);
      mappedClaims = java.util.Collections.unmodifiableMap(new java.util.TreeMap<>(mappedClaims));
    }
  }

  /** Diagnosed abstention; it carries no proof or classification capability. */
  /* default */ record Abstained(String rationale) implements Outcome {
    /* default */ Abstained {
      if (rationale == null || rationale.isBlank()) {
        throw new IllegalArgumentException("rationale must be nonblank");
      }
    }
  }
}
