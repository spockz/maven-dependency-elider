/* WHY: Writes a per-artifact JAR containing the proven retained classes, preserved resources, and
 * valid manifest data after signature invalidation. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactDigests;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Objects;
import java.util.Set;

/** Writes sanitized dependency JARs without merging artifact boundaries. */
// WHY: Distinct public preparation modes preserve callers' explicit output contracts.
@SuppressWarnings({"PMD.CommentSize", "PMD.TooManyMethods"})
public final class ArchiveSanitizer {
  /** Creates a stateless archive sanitizer. */
  public ArchiveSanitizer() {
    // Stateless sanitizer.
  }

  /** Writes archive content and records input and output hashes. */
  public ArtifactTrimRecord sanitize(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    final PreparedOutput prepared = prepare(originalJar, trimmedJar, coordinate, analysis);
    try {
      return publish(prepared);
    } finally {
      discard(prepared);
    }
  }

  /** Stages sanitized bytes without publishing them. */
  public PreparedOutput prepare(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    validateInputs(originalJar, trimmedJar, coordinate, analysis);
    final ArtifactDigests originalDigests = ArtifactDigests.read(originalJar);
    return prepareValidated(
        originalJar,
        trimmedJar,
        coordinate,
        analysis,
        originalDigests,
        null,
        false,
        "not_multi_release",
        Set.of());
  }

  /** Stages an MRJAR using a validated target-release elevation plan. */
  public PreparedOutput prepareMultiRelease(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final MultiReleaseArchivePlan plan)
      throws IOException {
    validateInputs(originalJar, trimmedJar, coordinate, analysis);
    Objects.requireNonNull(plan, "plan");
    final ArtifactDigests originalDigests = plan.sourceDigests();
    if (!plan.matches(originalJar, originalDigests.sha256())) {
      throw new IOException(
          "MRJAR elevation plan does not match original dependency: " + originalJar);
    }
    if (analysis.totalClasses() != plan.targetClasses().size()
        || !analysis.retainedClasses().equals(plan.retainedTargetClasses())) {
      throw new IOException("Trim analysis does not match the MRJAR target-release view");
    }
    return prepareValidated(
        originalJar,
        trimmedJar,
        coordinate,
        analysis,
        originalDigests,
        plan,
        false,
        "elevated_and_trimmed",
        Set.of());
  }

  /**
   * Stages an archive using provenance already captured by the caller.
   *
   * <p>The caller keeps the source stable for this build invocation.
   */
  public PreparedOutput prepareWithProvenance(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests)
      throws IOException {
    return prepareWithProvenance(
        originalJar, trimmedJar, coordinate, analysis, originalDigests, Set.of());
  }

  /** Stages a single-release archive while reconciling proven-absent providers. */
  public PreparedOutput prepareWithProvenance(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests,
      final Set<String> removedServiceProviders)
      throws IOException {
    return prepareWithCapturedDigests(
        originalJar,
        trimmedJar,
        coordinate,
        analysis,
        originalDigests,
        false,
        "not_multi_release",
        removedServiceProviders);
  }

  /** Stages a runtime derivative in classpath-only mode, stripping the root module descriptor. */
  public PreparedOutput prepareClasspathOnly(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests)
      throws IOException {
    return prepareClasspathOnly(
        originalJar, trimmedJar, coordinate, analysis, originalDigests, Set.of());
  }

  /** Stages a classpath-only archive while reconciling proven-absent providers. */
  public PreparedOutput prepareClasspathOnly(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests,
      final Set<String> removedServiceProviders)
      throws IOException {
    return prepareWithCapturedDigests(
        originalJar,
        trimmedJar,
        coordinate,
        analysis,
        originalDigests,
        true,
        "classpath-only",
        removedServiceProviders);
  }

  private PreparedOutput prepareWithCapturedDigests(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests,
      final boolean stripRootModuleDescriptor,
      final String mrjarStatus,
      final Set<String> removedServiceProviders)
      throws IOException {
    validateInputs(originalJar, trimmedJar, coordinate, analysis);
    Objects.requireNonNull(originalDigests, "originalDigests");
    Objects.requireNonNull(removedServiceProviders, "removedServiceProviders");
    if (!originalDigests.matchesPath(originalJar)) {
      throw new IOException(
          "Captured original dependency digests belong to a different path: " + originalJar);
    }
    return prepareValidated(
        originalJar,
        trimmedJar,
        coordinate,
        analysis,
        originalDigests,
        null,
        stripRootModuleDescriptor,
        mrjarStatus,
        removedServiceProviders);
  }

  private static void validateInputs(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis)
      throws IOException {
    Objects.requireNonNull(originalJar, "originalJar");
    Objects.requireNonNull(trimmedJar, "trimmedJar");
    Objects.requireNonNull(coordinate, "coordinate");
    Objects.requireNonNull(analysis, "analysis");
    if (!Files.isRegularFile(originalJar)) {
      throw new IOException("Original dependency is not a regular JAR file: " + originalJar);
    }
    if (analysis.retainedClasses().size() > analysis.totalClasses()) {
      throw new IOException("Trim analysis has more retained classes than total classes");
    }
  }

  private PreparedOutput prepareValidated(
      final Path originalJar,
      final Path trimmedJar,
      final ArtifactCoordinate coordinate,
      final DependencyJarTrimmer.TrimAnalysis analysis,
      final ArtifactDigests originalDigests,
      final MultiReleaseArchivePlan elevationPlan,
      final boolean stripRootModuleDescriptor,
      final String mrjarStatus,
      final Set<String> removedServiceProviders)
      throws IOException {
    final ArchiveOutputStager.OutputLocation location =
        ArchiveOutputStager.resolveOutputLocation(originalJar, trimmedJar);
    final Path temporaryJar = Files.createTempFile(location.directory(), ".trimmed-", ".jar.tmp");
    boolean moved = false;
    try {
      final ArchiveOutputStager.WriteResult writeResult =
          ArchiveOutputStager.writeAndMeasure(
              originalJar,
              temporaryJar,
              analysis,
              elevationPlan,
              stripRootModuleDescriptor,
              removedServiceProviders);
      moved = true;
      return new PreparedOutput(
          temporaryJar,
          location.outputPath(),
          location.originalPath(),
          coordinate,
          originalDigests.sha256(),
          originalDigests.sha1(),
          writeResult.trimmedDigests().sha256(),
          writeResult.trimmedDigests().sha1(),
          writeResult.totalClasses(),
          writeResult.retainedClasses(),
          writeResult.prunedClassBytes(),
          writeResult.originalPhysicalEntries(),
          writeResult.trimmedPhysicalEntries(),
          mrjarStatus);
    } finally {
      if (!moved) {
        Files.deleteIfExists(temporaryJar);
      }
    }
  }

  /** Publishes staged archive bytes and returns provenance. */
  public ArtifactTrimRecord publish(final PreparedOutput prepared) throws IOException {
    Objects.requireNonNull(prepared, "prepared");
    moveIntoPlace(prepared.temporaryJar(), prepared.outputPath());
    return new ArtifactTrimRecord(
        prepared.coordinate(),
        prepared.originalPath(),
        prepared.originalSha256(),
        prepared.originalSha1(),
        prepared.outputPath(),
        prepared.trimmedSha256(),
        prepared.trimmedSha1(),
        prepared.totalClasses(),
        prepared.retainedClasses(),
        prepared.prunedClassBytes(),
        prepared.originalPhysicalEntries(),
        prepared.trimmedPhysicalEntries(),
        prepared.mrjarStatus());
  }

  /** Removes an unpublished staged archive. */
  public void discard(final PreparedOutput prepared) throws IOException {
    Objects.requireNonNull(prepared, "prepared");
    Files.deleteIfExists(prepared.temporaryJar());
  }

  /** Holds staged archive metadata for validation and publication. */
  public record PreparedOutput(
      Path temporaryJar,
      Path outputPath,
      Path originalPath,
      ArtifactCoordinate coordinate,
      String originalSha256,
      String originalSha1,
      String trimmedSha256,
      String trimmedSha1,
      int totalClasses,
      int retainedClasses,
      long prunedClassBytes,
      int originalPhysicalEntries,
      int trimmedPhysicalEntries,
      String mrjarStatus) {}

  private static void moveIntoPlace(final Path temporaryJar, final Path trimmedJar)
      throws IOException {
    try {
      Files.move(
          temporaryJar,
          trimmedJar,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (final AtomicMoveNotSupportedException exception) {
      throw new IOException(
          "Filesystem cannot atomically publish the trimmed JAR: " + trimmedJar, exception);
    }
  }
}
