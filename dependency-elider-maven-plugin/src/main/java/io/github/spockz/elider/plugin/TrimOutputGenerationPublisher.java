// WHY: Keeps previous trimmed JAR generations selectable until a validated cache manifest
// commits.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.trimmer.ArtifactDigests;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Publishes a staged output generation. */
final class TrimOutputGenerationPublisher {
  /** PMD suppression name shared by package-private filesystem test seams. */
  private static final String DEFAULT_ACCESS_SUPPRESSION = "PMD.CommentDefaultAccessModifier";

  /** Injected move boundary used by commit-failure tests. */
  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  @FunctionalInterface
  interface MoveOperation {
    /** Moves one staged path into its publication location. */
    void move(Path source, Path target, boolean replace) throws IOException;
  }

  private TrimOutputGenerationPublisher() {
    throw new AssertionError("No instances");
  }

  /** Publishes staged output and commits its manifest. */
  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static TrimOutputGenerationCommitHandle publish(
      final Path stagedGeneration,
      final Path finalGeneration,
      final Path stagedManifest,
      final Path manifest,
      final MoveOperation move)
      throws IOException {
    final String manifestDigest = ArtifactDigests.read(stagedManifest).sha256();
    final Path backup = TrimOutputGenerationFileOps.backupPath(finalGeneration);
    final Path manifestBackup = TrimOutputGenerationFileOps.backupFilePath(manifest);
    boolean backedUpGeneration = false;
    boolean backedUpManifest = false;
    boolean installedGeneration = false;
    boolean manifestSwitchStarted = false;
    try {
      backedUpGeneration = backupExistingPath(finalGeneration, backup, move);
      backedUpManifest = backupExistingPath(manifest, manifestBackup, move);
      move.move(stagedGeneration, finalGeneration, false);
      installedGeneration = true;
      manifestSwitchStarted = true;
      commitManifest(stagedManifest, manifest, manifestDigest, move);
    } catch (final IOException failure) {
      rollbackFailedPublication(
          stagedGeneration,
          finalGeneration,
          backup,
          stagedManifest,
          manifest,
          manifestBackup,
          new PublicationState(
              backedUpGeneration, backedUpManifest, installedGeneration, manifestSwitchStarted),
          failure);
      throw failure;
    }
    return new TrimOutputGenerationCommitHandle(
        finalGeneration, backup, manifest, manifestBackup, backedUpGeneration, backedUpManifest);
  }

  private static boolean backupExistingPath(
      final Path path, final Path backup, final MoveOperation move) throws IOException {
    if (!Files.exists(path)) {
      return false;
    }
    move.move(path, backup, false);
    return true;
  }

  private static void commitManifest(
      final Path stagedManifest,
      final Path manifest,
      final String expectedDigest,
      final MoveOperation move)
      throws IOException {
    try {
      move.move(stagedManifest, manifest, true);
    } catch (final IOException exception) {
      if (!manifestMoveCompleted(stagedManifest, manifest, expectedDigest)) {
        throw exception;
      }
    }
  }

  private static boolean manifestMoveCompleted(
      final Path stagedManifest, final Path manifest, final String expectedDigest)
      throws IOException {
    return !Files.exists(stagedManifest)
        && Files.isRegularFile(manifest)
        && expectedDigest.equals(ArtifactDigests.read(manifest).sha256());
  }

  private static void rollbackManifest(
      final Path manifest, final Path backup, final boolean backedUp, final IOException failure) {
    try {
      if (backedUp) {
        TrimOutputGenerationFileOps.atomicMove(backup, manifest, true);
      } else {
        Files.deleteIfExists(manifest);
      }
    } catch (final IOException exception) {
      failure.addSuppressed(exception);
    }
  }

  private static void rollback(
      final Path generation,
      final Path backup,
      final boolean installed,
      final boolean backedUp,
      final IOException failure) {
    if (installed) {
      try {
        TrimOutputGenerationFileOps.deleteTree(generation);
      } catch (final IOException rollbackFailure) {
        failure.addSuppressed(rollbackFailure);
      }
    }
    if (backedUp) {
      try {
        TrimOutputGenerationFileOps.atomicMove(backup, generation, false);
      } catch (final IOException rollbackFailure) {
        failure.addSuppressed(rollbackFailure);
      }
    }
  }

  private static void rollbackFailedPublication(
      final Path stagedGeneration,
      final Path generation,
      final Path generationBackup,
      final Path stagedManifest,
      final Path manifest,
      final Path manifestBackup,
      final PublicationState beforeFailure,
      final IOException failure) {
    final PublicationState observed =
        beforeFailure.reconcile(
            stagedGeneration,
            generation,
            generationBackup,
            stagedManifest,
            manifest,
            manifestBackup);
    rollback(
        generation,
        generationBackup,
        observed.installedGeneration(),
        observed.backedUpGeneration(),
        failure);
    if (observed.backedUpManifest() || observed.manifestSwitchStarted()) {
      rollbackManifest(manifest, manifestBackup, observed.backedUpManifest(), failure);
    }
  }

  private record PublicationState(
      boolean backedUpGeneration,
      boolean backedUpManifest,
      boolean installedGeneration,
      boolean manifestSwitchStarted) {
    private PublicationState reconcile(
        final Path stagedGeneration,
        final Path generation,
        final Path generationBackup,
        final Path stagedManifest,
        final Path manifest,
        final Path manifestBackup) {
      return new PublicationState(
          backedUpGeneration || (Files.exists(generationBackup) && !Files.exists(generation)),
          backedUpManifest || (Files.exists(manifestBackup) && !Files.exists(manifest)),
          installedGeneration || (!Files.exists(stagedGeneration) && Files.exists(generation)),
          manifestSwitchStarted || !Files.exists(stagedManifest));
    }
  }

  /** Package-private injection point for the trimmer's publication boundary. */
  @SuppressWarnings(DEFAULT_ACCESS_SUPPRESSION)
  static void atomicMove(final Path source, final Path target, final boolean replace)
      throws IOException {
    TrimOutputGenerationFileOps.atomicMove(source, target, replace);
  }
}
