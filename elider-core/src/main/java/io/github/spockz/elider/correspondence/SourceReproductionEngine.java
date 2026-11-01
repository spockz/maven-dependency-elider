// WHY: Reproduces source archives in core without accepting plugin approval or Maven resolver
// types.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.model.ArtifactCoordinate;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Reproduces one exact source archive using the core's pinned compiler identity. */
public final class SourceReproductionEngine {
  /** JAR extension allowed by the initial non-transformed Java source path. */
  private static final String JAR_TYPE = "jar";

  /** Maven classifier resolved for source/build correspondence. */
  private static final String SOURCES_CLASSIFIER = "sources";

  /** Compiler image is captured once for the enclosing assessment invocation. */
  private final SourceJdkIdentity.Resolution compilerIdentity;

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

  private static SourceReproductionResult.Completed reproduceStrict(
      final SourceReproductionRequest request, final SourceJdkIdentity.Identity compilerIdentity)
      throws IOException {
    validateCoordinates(request.candidate(), request.sourcesCoordinate());
    final Path originalPath = requireJar(request.originalJar(), "original artifact");
    final Path sourcePath = requireJar(request.sourcesJar(), "sources artifact");
    final String originalSha256 = SourceFileDigest.sha256(originalPath);
    final String sourceSha256 = SourceFileDigest.sha256(sourcePath);
    final SourceCorrespondenceArchive original =
        SourceCorrespondenceArchiveReader.readOriginal(originalPath);
    final SourceCorrespondenceArchive sources =
        SourceCorrespondenceArchiveReader.readSources(sourcePath);
    requireStableArchive("original", originalSha256, original.sha256());
    requireStableArchive("sources", sourceSha256, sources.sha256());
    final Map<String, String> mappedFiles =
        SourceCorrespondencePathMapper.map(
            request.sourceClaims(), sources.sourceEntries(), request.conventionalLayoutAssumed());
    requireClaimPresence(request.sourceClaims(), request.routineClaims(), sources);
    final SourceUnitCompiler.Compilation compilation =
        SourceUnitCompiler.compile(sources, originalPath, compilerIdentity);
    SourceUnitIdentityValidator.requireUnique(compilation.units());
    SourceCorrespondenceAdmission.requireUniqueRoutineOwners(
        compilation.units(), request.routineClaims());
    SourceCorrespondenceAdmission.requireInventoryMatch(original.classes(), compilation.units());
    requireStableArchive("original", originalSha256, SourceFileDigest.sha256(originalPath));
    requireStableArchive("sources", sourceSha256, SourceFileDigest.sha256(sourcePath));
    return new SourceReproductionResult.Completed(
        request.candidate(),
        request.sourcesCoordinate(),
        request.sourceRepositoryProvenance(),
        originalSha256,
        sourceSha256,
        compilation.compilerIdentity(),
        compilation.options(),
        original.classes(),
        compilation.units(),
        mappedFiles);
  }

  private static void validateCoordinates(
      final ArtifactCoordinate candidate, final ArtifactCoordinate sourceCoordinate)
      throws IOException {
    if (candidate.version() == null || candidate.version().isBlank()) {
      throw new IOException("Exact candidate version is required");
    }
    final boolean matches =
        candidate.groupId().equals(sourceCoordinate.groupId())
            && candidate.artifactId().equals(sourceCoordinate.artifactId())
            && candidate.version().equals(sourceCoordinate.version())
            && JAR_TYPE.equals(candidate.type())
            && candidate.classifier().isEmpty()
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
    if (files.isEmpty() && routines.isEmpty()) {
      throw new IOException("At least one structured source or routine claim is required");
    }
    if (sources.sourceEntries().isEmpty()) {
      throw new IOException("Sources archive contains no Java source units");
    }
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
}
