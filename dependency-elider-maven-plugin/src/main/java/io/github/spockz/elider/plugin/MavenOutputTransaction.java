/* WHY: Keeps reports and project views recoverable until the resolver plan is activated. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Stages report files and restores prior files if a later publication step fails. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MavenOutputTransaction implements AutoCloseable {
  /** Ordered staged-to-final mapping preserves publication and rollback order. */
  private final Map<Path, Path> stagedToFinal;

  /** File journal records completed moves even if an injected move then throws. */
  private final MavenOutputFileJournal journal;

  /** Targets removed transactionally when a generated document is no longer eligible. */
  private final Map<Path, String> deleteTargets = new LinkedHashMap<>();

  /** Targets intentionally left untouched when cleanup is not backed by ownership evidence. */
  private final Set<Path> skippedTargets = new LinkedHashSet<>();

  /** Whether all staged targets were installed. */
  private boolean published;

  /** Whether outputs became authoritative. */
  private boolean committed;

  /** Whether rollback finished without errors. */
  private boolean rolledBack;

  /** Filesystem move seam for transaction failure tests. */
  @FunctionalInterface
  interface MoveOperation {
    /** Moves one path into place. */
    void move(Path source, Path target) throws IOException;
  }

  private MavenOutputTransaction(
      final Map<Path, Path> stagedToFinal, final MoveOperation moveOperation) {
    this.stagedToFinal = MavenOutputTargetPaths.orderedImmutable(stagedToFinal);
    this.journal = new MavenOutputFileJournal(moveOperation);
  }

  static MavenOutputTransaction forTargets(final List<Path> targets) throws IOException {
    return forTargets(targets, MavenOutputFileMover::move);
  }

  static MavenOutputTransaction forTargets(
      final List<Path> targets, final MoveOperation moveOperation) throws IOException {
    return new MavenOutputTransaction(
        MavenOutputTargetPaths.createStagingMap(targets, UUID.randomUUID().toString()),
        moveOperation);
  }

  Path stagedPath(final Path target) throws IOException {
    final Path absolute = target.toAbsolutePath().normalize();
    return stagedToFinal.entrySet().stream()
        .filter(entry -> entry.getValue().equals(absolute))
        .map(Map.Entry::getKey)
        .findFirst()
        .orElseThrow(() -> new IOException("Output was not staged: " + absolute));
  }

  List<Path> stagingPaths() {
    return List.copyOf(stagedToFinal.keySet());
  }

  void deleteTarget(final Path target, final String expectedSha256) throws IOException {
    if (published) {
      throw new IllegalStateException("Output transaction is already published");
    }
    final Path absolute = target.toAbsolutePath().normalize();
    if (!stagedToFinal.containsValue(absolute)) {
      throw new IOException("Output was not staged: " + absolute);
    }
    if (expectedSha256 == null || !expectedSha256.matches("[0-9a-f]{64}")) {
      throw new IOException("Output deletion requires a SHA-256 ownership digest: " + absolute);
    }
    skippedTargets.remove(absolute);
    deleteTargets.put(absolute, expectedSha256);
  }

  void skipTarget(final Path target) throws IOException {
    if (published) {
      throw new IllegalStateException("Output transaction is already published");
    }
    final Path absolute = target.toAbsolutePath().normalize();
    if (!stagedToFinal.containsValue(absolute)) {
      throw new IOException("Output was not staged: " + absolute);
    }
    deleteTargets.remove(absolute);
    skippedTargets.add(absolute);
  }

  void publish() throws IOException {
    if (published) {
      throw new IllegalStateException("Staged output transaction is already published");
    }
    try {
      for (final Map.Entry<Path, Path> entry : stagedToFinal.entrySet()) {
        if (deleteTargets.containsKey(entry.getValue())) {
          journal.deleteExisting(entry.getValue(), deleteTargets.get(entry.getValue()));
        } else if (!skippedTargets.contains(entry.getValue())) {
          journal.installStaged(entry.getKey(), entry.getValue());
        }
      }
      published = true;
    } catch (final IOException exception) {
      try {
        rollback();
      } catch (final IOException rollbackFailure) {
        exception.addSuppressed(rollbackFailure);
      }
      throw exception;
    }
  }

  void commit() {
    committed = true;
  }

  void cleanupCommitted() throws IOException {
    journal.cleanupCommitted(stagedToFinal.keySet());
  }

  @Override
  public void close() throws IOException {
    if (!committed) {
      rollback();
    }
  }

  private void rollback() throws IOException {
    if (rolledBack) {
      return;
    }
    final IOException failure = journal.rollback(stagedToFinal.keySet());
    if (failure != null) {
      throw failure;
    }
    rolledBack = true;
  }
}
