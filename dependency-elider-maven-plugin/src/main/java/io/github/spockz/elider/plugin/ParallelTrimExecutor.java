/* WHY: Preserves input ordering and bounded cancellation while delaying
 * cleanup until detached workers stop writing. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.TrimOutputCoordinator.PendingOutput;
import io.github.spockz.elider.trimmer.ArchiveSanitizer;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Runs bounded candidate work and preserves canonical result ordering. */
final class ParallelTrimExecutor {
  /** Limits the existing J2EE exception to actual worker lifecycle methods. */
  private static final String DO_NOT_USE_THREADS_SUPPRESSION = "PMD.DoNotUseThreads";

  private ParallelTrimExecutor() {}

  /* package */ record IndexedResult<R>(int index, R value) {}

  /** Runs cleanup only after workers can no longer access staged files. */
  /* package */ @FunctionalInterface
  interface CleanupAction {
    /** Releases one staged operation resource. */
    void run() throws IOException;
  }

  /** Owns staged files and defers cleanup until cancelled workers stop writing. */
  /* package */ static final class PreparedOutputCleanup implements AutoCloseable {
    /** Owns discard operations for all successfully prepared archives. */
    private final ArchiveSanitizer sanitizer;

    /** Receives prepared files from isolated worker tasks before cleanup. */
    private final Queue<PendingOutput> pendingOutputs = new ConcurrentLinkedQueue<>();

    /** Runs operation cleanup after archive staging files are discarded. */
    private final List<CleanupAction> cleanupActions = new ArrayList<>();

    /** Deferred termination keeps staged files alive while a worker may still write. */
    private DeferredTermination deferredTermination;

    /* package */ PreparedOutputCleanup(final ArchiveSanitizer sanitizer) {
      this.sanitizer = sanitizer;
    }

    /* package */ PendingOutput track(final PendingOutput pending) {
      pendingOutputs.add(pending);
      return pending;
    }

    /* package */ void addCleanupAction(final CleanupAction cleanupAction) {
      cleanupActions.add(cleanupAction);
    }

    private void deferUntil(final DeferredTermination termination) {
      deferredTermination = termination;
    }

    @Override
    @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
    public void close() throws IOException {
      if (deferredTermination != null && !deferredTermination.terminated()) {
        final DeferredTermination termination = deferredTermination;
        Thread.ofVirtual()
            .name("dependency-elider-staging-cleanup")
            .start(
                () -> {
                  termination.awaitStopped();
                  try {
                    cleanupResources();
                  } catch (final IOException exception) {
                    System.getLogger(MavenDependencyTrimmer.class.getName())
                        .log(
                            System.Logger.Level.ERROR,
                            "Could not clean deferred trim staging",
                            exception);
                  }
                });
        return;
      }
      cleanupResources();
    }

    private void cleanupResources() throws IOException {
      IOException cleanupFailure = null;
      for (final PendingOutput pending : pendingOutputs) {
        try {
          sanitizer.discard(pending.prepared());
        } catch (final IOException exception) {
          cleanupFailure = ParallelTrimFailures.appendFailure(cleanupFailure, exception);
        }
      }
      for (final CleanupAction cleanupAction : cleanupActions) {
        try {
          cleanupAction.run();
        } catch (final IOException exception) {
          cleanupFailure = ParallelTrimFailures.appendFailure(cleanupFailure, exception);
        }
      }
      if (cleanupFailure != null) {
        throw cleanupFailure;
      }
    }
  }

  private static int trimParallelism(final int workSize, final int maxWorkers) {
    if (workSize <= MavenDependencyTrimmer.MIN_TRIM_WORKERS) {
      return 1;
    }
    final int available = Runtime.getRuntime().availableProcessors();
    return Math.max(1, Math.min(Math.min(available, maxWorkers), workSize));
  }

  /* package */ static <T, R> List<R> mapParallel(
      final List<T> items, final int maxWorkers, final TrimWorkItem<T, R> task) throws IOException {
    return mapParallel(items, maxWorkers, task, null);
  }

  /* package */ @SuppressWarnings({
    "PMD.AvoidCatchingGenericException",
    "PMD.CloseResource",
    DO_NOT_USE_THREADS_SUPPRESSION
  })
  static <T, R> List<R> mapParallel(
      final List<T> items,
      final int maxWorkers,
      final TrimWorkItem<T, R> task,
      final PreparedOutputCleanup deferredCleanup)
      throws IOException {
    final int parallelism = trimParallelism(items.size(), maxWorkers);
    if (parallelism == MavenDependencyTrimmer.MIN_TRIM_WORKERS) {
      return executeSequential(
          items,
          item -> {
            try {
              return task.execute(item);
            } catch (final IOException | RuntimeException exception) {
              throw ParallelTrimFailures.parallelTaskFailure(exception);
            }
          });
    }
    final ExecutorService executor =
        Executors.newFixedThreadPool(
            parallelism,
            Thread.ofPlatform().daemon().name("dependency-elider-worker-", 0).factory());
    try {
      final CompletionService<IndexedResult<R>> completions =
          new ExecutorCompletionService<>(executor);
      final List<Future<IndexedResult<R>>> active = new ArrayList<>(parallelism);
      try {
        final List<R> results =
            ParallelTrimWorkQueue.executeTasks(
                items,
                parallelism,
                task,
                completions,
                active,
                () -> cancelParallelWork(executor, active, deferredCleanup),
                () -> Thread.currentThread().interrupt());
        executor.shutdown();
        return List.copyOf(results);
      } catch (final RuntimeException | Error failure) {
        ParallelTrimFailures.addCancellationTimeout(
            failure, cancelParallelWork(executor, active, deferredCleanup));
        throw failure;
      }
    } finally {
      if (!executor.isShutdown()) {
        executor.shutdownNow();
      }
    }
  }

  @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
  private static boolean cancelParallelWork(
      final ExecutorService executor,
      final List<? extends Future<?>> active,
      final PreparedOutputCleanup deferredCleanup) {
    active.forEach(future -> future.cancel(true));
    executor.shutdownNow();
    boolean interrupted = false;
    final long deadline =
        System.nanoTime()
            + TimeUnit.SECONDS.toNanos(ParallelTrimFailures.CANCELLATION_GRACE_SECONDS);
    while (!executor.isTerminated()) {
      final long remainingNanos = deadline - System.nanoTime();
      if (remainingNanos <= 0) {
        break;
      }
      try {
        executor.awaitTermination(remainingNanos, TimeUnit.NANOSECONDS);
      } catch (final InterruptedException exception) {
        interrupted = true;
      }
    }
    final boolean terminated = executor.isTerminated();
    if (!terminated && deferredCleanup != null) {
      deferredCleanup.deferUntil(
          new DeferredTermination() {
            @Override
            public boolean terminated() {
              return executor.isTerminated();
            }

            @Override
            public void awaitStopped() {
              awaitTerminationUninterruptibly(executor);
              executor.close();
            }
          });
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
    return terminated;
  }

  @SuppressWarnings(DO_NOT_USE_THREADS_SUPPRESSION)
  private static void awaitTerminationUninterruptibly(final ExecutorService executor) {
    boolean interrupted = false;
    while (!executor.isTerminated()) {
      try {
        executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
      } catch (final InterruptedException exception) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  /** Allows staging cleanup to wait without owning the worker executor. */
  private interface DeferredTermination {
    /** Reports whether workers have stopped touching staged files. */
    boolean terminated();

    /** Waits for all workers to stop and releases executor resources. */
    void awaitStopped();
  }

  private static <T, R> List<R> executeSequential(
      final List<T> items, final TrimWorkItem<T, R> task) throws IOException {
    final List<R> results = new ArrayList<>(items.size());
    for (final T item : items) {
      results.add(task.execute(item));
    }
    return List.copyOf(results);
  }
}
