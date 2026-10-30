// WHY: Proves staged report publication restores earlier targets when a later move fails.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Verifies multi-file report rollback and target validation. */
final class MavenOutputTransactionTest {
  /** Shared report filename for transaction paths. */
  private static final String SUMMARY_FILE = "summary.json";

  /** Stage suffix used to identify the source side of an injected move. */
  private static final String STAGED_SUFFIX = ".staged-";

  /** Previous report content used by rollback assertions. */
  private static final String PREVIOUS_REPORT = "previous report";

  /** Previous OpenVEX content used by rollback assertions. */
  private static final String PREVIOUS_OPENVEX = "previous OpenVEX";

  /** PMD rule for assertions spanning one filesystem transaction invariant. */
  private static final String ASSERTION_SUPPRESSION = "PMD.UnitTestContainsTooManyAsserts";

  /** Temporary root isolates report publication and rollback files. */
  @TempDir private Path temporaryDirectory;

  /** Creates the file-transaction fixture. */
  @SuppressWarnings({"PMD.UncommentedEmptyConstructor", "PMD.CommentDefaultAccessModifier"})
  MavenOutputTransactionTest() {}

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks rollback of every file after one publication failure.
  void failureAfterFirstTargetInstallRestoresEveryPreviousFile() throws Exception {
    final Path firstTarget = temporaryDirectory.resolve("class-report.json");
    final Path secondTarget = temporaryDirectory.resolve(SUMMARY_FILE);
    Files.writeString(firstTarget, "old class report");
    Files.writeString(secondTarget, "old summary");
    final AtomicBoolean injected = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, target) -> {
          if (source.getFileName().toString().contains(STAGED_SUFFIX)
              && target.equals(secondTarget)
              && injected.compareAndSet(false, true)) {
            throw new IOException("injected second target failure");
          }
          Files.move(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(firstTarget, secondTarget), move)) {
      Files.writeString(transaction.stagedPath(firstTarget), "new class report");
      Files.writeString(transaction.stagedPath(secondTarget), "new summary");
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("injected second target failure");
    }

    assertThat(injected).isTrue();
    assertThat(firstTarget).hasContent("old class report");
    assertThat(secondTarget).hasContent("old summary");
    try (java.util.stream.Stream<Path> files = Files.list(temporaryDirectory)) {
      assertThat(files.map(path -> path.getFileName().toString()).toList())
          .containsExactlyInAnyOrder("class-report.json", SUMMARY_FILE);
    }
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks validation before staging changes the filesystem.
  void overlappingAndExistingDirectoryTargetsAreRejectedBeforeStaging() throws Exception {
    final Path directoryTarget = Files.createDirectory(temporaryDirectory.resolve("reports"));
    final Path nestedTarget = directoryTarget.resolve(SUMMARY_FILE);

    assertThatThrownBy(
            () -> MavenOutputTransaction.forTargets(List.of(directoryTarget, nestedTarget)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("existing directory");
    assertThat(nestedTarget).doesNotExist();
    assertThatThrownBy(() -> MavenOutputTransaction.forTargets(List.of(nestedTarget, nestedTarget)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Duplicate output target");
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks a completed backup move is recognized and restored.
  void backupMoveThatCompletesThenThrowsRestoresPreviousFile() throws Exception {
    final Path target = temporaryDirectory.resolve(SUMMARY_FILE);
    Files.writeString(target, "previous summary");
    final AtomicBoolean injected = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, destination) -> {
          Files.move(source, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
          if (source.equals(target)
              && destination.getFileName().toString().contains(".backup-")
              && injected.compareAndSet(false, true)) {
            throw new IOException("injected completed backup move failure");
          }
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(target), move)) {
      Files.writeString(transaction.stagedPath(target), "new summary");
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("completed backup move failure");
    }

    assertThat(target).hasContent("previous summary");
    assertThat(injected).isTrue();
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks a completed install move is removed after failure.
  void firstInstallMoveThatCompletesThenThrowsRemovesUncommittedTarget() throws Exception {
    final Path target = temporaryDirectory.resolve("first-report.json");
    final AtomicBoolean injected = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, destination) -> {
          Files.move(source, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
          if (source.getFileName().toString().contains(STAGED_SUFFIX)
              && destination.equals(target)
              && injected.compareAndSet(false, true)) {
            throw new IOException("injected completed install move failure");
          }
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(target), move)) {
      Files.writeString(transaction.stagedPath(target), "new report");
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("completed install move failure");
    }

    assertThat(target).doesNotExist();
    assertThat(injected).isTrue();
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks the journal verifies bytes after a move operation reports success.
  void normalInstallMoveWithDifferentBytesRollsBack() throws Exception {
    final Path target = temporaryDirectory.resolve("verified-report.json");
    Files.writeString(target, PREVIOUS_REPORT);
    final MavenOutputTransaction.MoveOperation move =
        (source, destination) -> {
          Files.move(source, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
          if (destination.equals(target)
              && source.getFileName().toString().contains(STAGED_SUFFIX)) {
            Files.writeString(destination, "different installed bytes");
          }
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(target), move)) {
      final Path stage = transaction.stagedPath(target);
      Files.writeString(stage, "expected report");
      final java.util.Map<Path, String> expected = transaction.captureStageDigests(List.of(stage));
      assertThatThrownBy(() -> transaction.publish(expected))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("Installed output digest differs from frozen stage");
    }

    assertThat(target).hasContent(PREVIOUS_REPORT);
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks stale-output deletion is restored if a later publication move fails.
  void failedPublicationRestoresTransactionallyDeletedOutput() throws Exception {
    final Path staleVex = temporaryDirectory.resolve("dependency-elider.openvex.json");
    final Path report = temporaryDirectory.resolve(SUMMARY_FILE);
    Files.writeString(staleVex, PREVIOUS_OPENVEX);
    Files.writeString(report, PREVIOUS_REPORT);
    final AtomicBoolean failed = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, target) -> {
          if (source.getFileName().toString().contains(STAGED_SUFFIX)
              && target.equals(report)
              && failed.compareAndSet(false, true)) {
            throw new IOException("injected report installation failure");
          }
          Files.move(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(staleVex, report), move)) {
      transaction.deleteTarget(staleVex, ArtifactFileDigest.sha256(staleVex));
      Files.writeString(transaction.stagedPath(report), "new report");
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("injected report installation failure");
    }

    assertThat(staleVex).hasContent(PREVIOUS_OPENVEX);
    assertThat(report).hasContent(PREVIOUS_REPORT);
    assertThat(failed).isTrue();
  }

  @Test
  void skippedTargetNeedsNoStageAndRemainsUnchanged() throws Exception {
    final Path userFile = temporaryDirectory.resolve("user-owned.openvex.json");
    Files.writeString(userFile, "user-owned OpenVEX");

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(userFile))) {
      transaction.skipTarget(userFile);
      transaction.publish();
      transaction.commit();
      transaction.cleanupCommitted();
    }

    assertThat(userFile).hasContent("user-owned OpenVEX");
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  void failedStaleOutputDeletionRestoresCompletedBackupMove() throws Exception {
    final Path staleVex = temporaryDirectory.resolve("dependency-elider.openvex.json");
    Files.writeString(staleVex, PREVIOUS_OPENVEX);
    final AtomicBoolean failed = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, target) -> {
          Files.move(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
          if (source.equals(staleVex)
              && target.getFileName().toString().contains(".backup-")
              && failed.compareAndSet(false, true)) {
            throw new IOException("injected stale VEX deletion failure");
          }
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(staleVex), move)) {
      transaction.deleteTarget(staleVex, ArtifactFileDigest.sha256(staleVex));
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("injected stale VEX deletion failure");
    }

    assertThat(staleVex).hasContent(PREVIOUS_OPENVEX);
    assertThat(failed).isTrue();
  }

  @Test
  @SuppressWarnings(ASSERTION_SUPPRESSION)
  // Checks retry preserves targets whose backups were restored already.
  void retryAfterPartialRestoreKeepsAlreadyRestoredFile() throws Exception {
    final Path firstTarget = temporaryDirectory.resolve("first.json");
    final Path secondTarget = temporaryDirectory.resolve("second.json");
    Files.writeString(firstTarget, "old first");
    Files.writeString(secondTarget, "old second");
    final AtomicBoolean installFailure = new AtomicBoolean();
    final AtomicBoolean restoreFailure = new AtomicBoolean();
    final MavenOutputTransaction.MoveOperation move =
        (source, destination) -> {
          if (source.getFileName().toString().contains(STAGED_SUFFIX)
              && destination.equals(secondTarget)
              && installFailure.compareAndSet(false, true)) {
            throw new IOException("injected install failure");
          }
          if (source.getFileName().toString().contains(".backup-")
              && destination.equals(secondTarget)
              && restoreFailure.compareAndSet(false, true)) {
            throw new IOException("injected restore failure");
          }
          Files.move(source, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        };

    try (MavenOutputTransaction transaction =
        MavenOutputTransaction.forTargets(List.of(firstTarget, secondTarget), move)) {
      Files.writeString(transaction.stagedPath(firstTarget), "new first");
      Files.writeString(transaction.stagedPath(secondTarget), "new second");
      assertThatThrownBy(transaction::publish)
          .isInstanceOf(IOException.class)
          .hasMessageContaining("injected install failure")
          .satisfies(
              failure ->
                  assertThat(failure.getSuppressed())
                      .anySatisfy(
                          suppressed ->
                              assertThat(suppressed)
                                  .hasMessageContaining("injected restore failure")));
      assertThat(firstTarget).hasContent("old first");
    }

    assertThat(installFailure).isTrue();
    assertThat(restoreFailure).isTrue();
    assertThat(firstTarget).hasContent("old first");
    assertThat(secondTarget).hasContent("old second");
  }
}
