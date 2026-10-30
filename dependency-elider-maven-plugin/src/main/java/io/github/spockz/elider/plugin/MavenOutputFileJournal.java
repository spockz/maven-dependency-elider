// WHY: Tracks per-target moves so failed rollback can safely resume without deleting restored data.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Owns report backup, install, rollback, and post-commit cleanup state. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenOutputFileJournal {
  /** Filesystem operation injected by the output transaction. */
  private final MavenOutputTransaction.MoveOperation moveOperation;

  /** Ordered because restoration must follow the same deterministic target sequence. */
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private final Map<Path, Path> backups = new LinkedHashMap<>();

  /** Paths installed by this transaction and not yet removed or restored. */
  private final List<Path> installed = new ArrayList<>();

  MavenOutputFileJournal(final MavenOutputTransaction.MoveOperation moveOperation) {
    this.moveOperation = moveOperation;
  }

  void backupExisting(final Path target) throws IOException {
    if (!Files.exists(target)) {
      return;
    }
    final Path backup =
        target.resolveSibling("." + target.getFileName() + ".backup-" + UUID.randomUUID());
    try {
      moveOperation.move(target, backup);
      backups.put(target, backup);
    } catch (final IOException failure) {
      if (!Files.exists(target) && Files.exists(backup)) {
        backups.put(target, backup);
      }
      throw failure;
    }
  }

  void installStaged(final Path staged, final Path target) throws IOException {
    if (!Files.isRegularFile(staged)) {
      throw new IOException("Staged output is missing: " + staged);
    }
    backupExisting(target);
    try {
      moveOperation.move(staged, target);
      installed.add(target);
    } catch (final IOException failure) {
      if (!Files.exists(staged) && Files.exists(target)) {
        installed.add(target);
      }
      throw failure;
    }
  }

  void deleteExisting(final Path target, final String expectedSha256) throws IOException {
    if (MavenPreconditionOutputState.definitelyAbsent(target)) {
      return;
    }
    if (!Files.isRegularFile(target)) {
      throw new IOException("Owned generated output is not a regular file: " + target);
    }
    backupExisting(target);
    final Path backup = backups.get(target);
    if (backup != null && !ArtifactFileDigest.sha256(backup).equals(expectedSha256)) {
      throw new IOException(
          "Owned generated output changed before transactional cleanup: " + target);
    }
  }

  IOException rollback(final Iterable<Path> stagedPaths) {
    IOException failure = removeInstalledTargets();
    failure = collectRestoreFailures(failure);
    failure = MavenOutputFileCleanup.delete(stagedPaths, failure);
    return failure;
  }

  void cleanupCommitted(final Iterable<Path> stagedPaths) throws IOException {
    IOException failure = MavenOutputFileCleanup.delete(backups.values(), null);
    failure = MavenOutputFileCleanup.delete(stagedPaths, failure);
    if (failure != null) {
      throw failure;
    }
    backups.clear();
    installed.clear();
  }

  private IOException removeInstalledTargets() {
    IOException failure = null;
    for (final Path target : List.copyOf(installed).reversed()) {
      try {
        Files.deleteIfExists(target);
        installed.remove(target);
      } catch (final IOException exception) {
        failure = MavenOutputFileCleanup.append(failure, exception);
      }
    }
    return failure;
  }

  private IOException collectRestoreFailures(final IOException existingFailure) {
    IOException failure = existingFailure;
    for (final Map.Entry<Path, Path> entry : List.copyOf(backups.entrySet())) {
      final IOException restoreFailure = restoreBackup(entry);
      if (restoreFailure != null) {
        failure = MavenOutputFileCleanup.append(failure, restoreFailure);
      }
    }
    return failure;
  }

  private IOException restoreBackup(final Map.Entry<Path, Path> entry) {
    try {
      moveOperation.move(entry.getValue(), entry.getKey());
      removeRestoredTargetState(entry.getKey());
      return null;
    } catch (final IOException failure) {
      if (!Files.exists(entry.getValue()) && Files.exists(entry.getKey())) {
        removeRestoredTargetState(entry.getKey());
        return null;
      }
      return failure;
    }
  }

  private void removeRestoredTargetState(final Path target) {
    backups.remove(target);
    installed.remove(target);
  }
}
