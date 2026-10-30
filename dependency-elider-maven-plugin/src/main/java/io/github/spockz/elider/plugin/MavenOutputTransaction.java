/* WHY: Keeps reports and project views recoverable until the resolver plan is activated. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Stages report files and restores prior files if a later publication step fails. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
// Target mutations and their rollback state must share one transaction lifecycle.
final class MavenOutputTransaction implements AutoCloseable {
  /** Error text used when a final path was not reserved by this transaction. */
  private static final String OUTPUT_NOT_STAGED = "Output was not staged: ";

  /** Ordered staged-to-final mapping preserves publication and rollback order. */
  private final Map<Path, Path> stagedToFinal;

  /** File journal records completed moves even if an injected move then throws. */
  private final MavenOutputFileJournal journal;

  /** Targets removed transactionally when a generated document is no longer eligible. */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // Mutated only on the serialized publication path.
  private final Map<Path, String> deleteTargets = new HashMap<>();

  /** Targets left untouched when cleanup lacks ownership evidence. */
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
        .orElseThrow(() -> new IOException(OUTPUT_NOT_STAGED + absolute));
  }

  List<Path> stagingPaths() {
    return List.copyOf(stagedToFinal.keySet());
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Frozen digest map is consumed synchronously.
  Map<Path, String> captureStageDigests(final List<Path> installStages) throws IOException {
    final Map<Path, String> digests = new HashMap<>();
    for (final Path requestedStage : installStages) {
      final Path stage = requestedStage.toAbsolutePath().normalize();
      final Path target = stagedToFinal.get(stage);
      if (target == null) {
        throw new IOException("Output stage was not reserved: " + stage);
      }
      if (!Files.isRegularFile(stage)) {
        throw new IOException("Staged output is missing or not a regular file: " + stage);
      }
      if (digests.put(target, ArtifactFileDigest.sha256(stage)) != null) {
        throw new IOException("Output stage was included more than once: " + stage);
      }
    }
    return Map.copyOf(digests);
  }

  void verifyStageDigests(final Map<Path, String> expectedDigests) throws IOException {
    final Map<Path, String> frozen = immutableDigestPlan(expectedDigests);
    validateInstallTargets(frozen);
    for (final Map.Entry<Path, String> entry : frozen.entrySet()) {
      final Path stage = stageForTarget(entry.getKey());
      verifyDigest(stage, entry.getValue(), "Staged output changed after staging: ");
    }
  }

  void deleteTarget(final Path target, final String expectedSha256) throws IOException {
    if (published) {
      throw new IllegalStateException("Output transaction is already published");
    }
    final Path absolute = target.toAbsolutePath().normalize();
    if (!stagedToFinal.containsValue(absolute)) {
      throw new IOException(OUTPUT_NOT_STAGED + absolute);
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
      throw new IOException(OUTPUT_NOT_STAGED + absolute);
    }
    deleteTargets.remove(absolute);
    skippedTargets.add(absolute);
  }

  void publish() throws IOException {
    publish(captureStageDigests(activeStagePaths()));
  }

  void publish(final Map<Path, String> expectedDigests) throws IOException {
    if (published) {
      throw new IllegalStateException("Staged output transaction is already published");
    }
    final Map<Path, String> frozen = immutableDigestPlan(expectedDigests);
    validateInstallTargets(frozen);
    try {
      for (final Map.Entry<Path, Path> entry : stagedToFinal.entrySet()) {
        if (deleteTargets.containsKey(entry.getValue())) {
          journal.deleteExisting(entry.getValue(), deleteTargets.get(entry.getValue()));
        } else if (!skippedTargets.contains(entry.getValue())) {
          journal.installStaged(entry.getKey(), entry.getValue(), frozen.get(entry.getValue()));
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

  private List<Path> activeStagePaths() {
    return stagedToFinal.entrySet().stream()
        .filter(
            entry ->
                !deleteTargets.containsKey(entry.getValue())
                    && !skippedTargets.contains(entry.getValue()))
        .map(Map.Entry::getKey)
        .toList();
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Immutable snapshot has no concurrent writers.
  private Map<Path, String> immutableDigestPlan(final Map<Path, String> expectedDigests)
      throws IOException {
    final Map<Path, String> normalized = new HashMap<>();
    for (final Map.Entry<Path, String> entry : expectedDigests.entrySet()) {
      final Path target = entry.getKey().toAbsolutePath().normalize();
      final String digest = entry.getValue();
      if (digest == null || !digest.matches("[0-9a-f]{64}")) {
        throw new IOException("Output stage requires a SHA-256 digest: " + target);
      }
      if (!stagedToFinal.containsValue(target) || normalized.put(target, digest) != null) {
        throw new IOException(
            "Output stage digest plan contains an unknown or duplicate target: " + target);
      }
    }
    return Map.copyOf(normalized);
  }

  private void validateInstallTargets(final Map<Path, String> expectedDigests) throws IOException {
    final Set<Path> activeTargets = new LinkedHashSet<>();
    stagedToFinal.values().stream()
        .filter(target -> !deleteTargets.containsKey(target) && !skippedTargets.contains(target))
        .forEach(activeTargets::add);
    if (!activeTargets.equals(expectedDigests.keySet())) {
      throw new IOException("Output stage digest plan does not match the transaction install set");
    }
  }

  private Path stageForTarget(final Path target) throws IOException {
    return stagedToFinal.entrySet().stream()
        .filter(entry -> entry.getValue().equals(target))
        .map(Map.Entry::getKey)
        .findFirst()
        .orElseThrow(() -> new IOException(OUTPUT_NOT_STAGED + target));
  }

  private static void verifyDigest(
      final Path path, final String expectedDigest, final String mismatchMessage)
      throws IOException {
    if (!Files.isRegularFile(path) || !ArtifactFileDigest.sha256(path).equals(expectedDigest)) {
      throw new IOException(mismatchMessage + path);
    }
  }
}
