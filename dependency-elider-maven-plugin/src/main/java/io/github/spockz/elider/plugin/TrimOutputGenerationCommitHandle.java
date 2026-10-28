// WHY: Owns the prior output generation until reports, views, and the resolver plan commit.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Rolls a generation publisher back unless the caller commits publication. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class TrimOutputGenerationCommitHandle implements AutoCloseable {
  /** Newly installed output generation removed when publication aborts. */
  private final Path generation;

  /** Prior generation restored if the replacement fails. */
  private final Path generationBackup;

  /** Active trim manifest switched to the new generation. */
  private final Path manifest;

  /** Prior manifest restored on abort. */
  private final Path manifestBackup;

  /** Whether a generation existed before this publication. */
  private final boolean hadGeneration;

  /** Whether a manifest existed before this publication. */
  private final boolean hadManifest;

  /** Whether the caller made this generation authoritative. */
  private boolean committed;

  TrimOutputGenerationCommitHandle(
      final Path generation,
      final Path generationBackup,
      final Path manifest,
      final Path manifestBackup,
      final boolean hadGeneration,
      final boolean hadManifest) {
    this.generation = generation;
    this.generationBackup = generationBackup;
    this.manifest = manifest;
    this.manifestBackup = manifestBackup;
    this.hadGeneration = hadGeneration;
    this.hadManifest = hadManifest;
  }

  void commit() {
    committed = true;
  }

  void cleanupCommitted() throws IOException {
    IOException failure = null;
    try {
      TrimOutputGenerationFileOps.deleteTree(generationBackup);
    } catch (final IOException exception) {
      failure = exception;
    }
    try {
      TrimOutputGenerationFileOps.deleteTree(manifestBackup);
    } catch (final IOException exception) {
      failure = TrimOutputGenerationFileOps.append(failure, exception);
    }
    if (failure != null) {
      throw failure;
    }
  }

  @Override
  public void close() throws IOException {
    if (!committed) {
      rollback();
    }
  }

  private void rollback() throws IOException {
    IOException failure = removeGeneration();
    failure = restoreGeneration(failure);
    failure = restoreManifest(failure);
    if (failure != null) {
      throw failure;
    }
  }

  private IOException removeGeneration() {
    try {
      TrimOutputGenerationFileOps.deleteTree(generation);
      return null;
    } catch (final IOException exception) {
      return exception;
    }
  }

  private IOException restoreGeneration(final IOException failure) {
    if (hadGeneration && Files.exists(generationBackup)) {
      try {
        TrimOutputGenerationFileOps.atomicMove(generationBackup, generation, false);
      } catch (final IOException exception) {
        return TrimOutputGenerationFileOps.append(failure, exception);
      }
    }
    return failure;
  }

  private IOException restoreManifest(final IOException failure) {
    try {
      if (hadManifest && Files.exists(manifestBackup)) {
        TrimOutputGenerationFileOps.atomicMove(manifestBackup, manifest, true);
      } else {
        Files.deleteIfExists(manifest);
      }
    } catch (final IOException exception) {
      return TrimOutputGenerationFileOps.append(failure, exception);
    }
    return failure;
  }
}
