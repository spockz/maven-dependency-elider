/* WHY: Collects indexed task results before ordered publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.plugin.ParallelTrimExecutor.IndexedResult;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.function.BooleanSupplier;

/** Collects indexed task results before ordered publication. */
final class ParallelTrimWorkQueue {
  private ParallelTrimWorkQueue() {}

  /* package */ static <T, R> List<R> executeTasks(
      final List<T> items,
      final int parallelism,
      final TrimWorkItem<T, R> task,
      final CompletionService<IndexedResult<R>> completions,
      final List<Future<IndexedResult<R>>> active,
      final BooleanSupplier cancel,
      final Runnable interrupt)
      throws IOException {
    try {

      final List<R> results = new ArrayList<>(java.util.Collections.nCopies(items.size(), null));
      int nextIndex = 0;
      int completed = 0;
      while (completed < items.size()) {
        while (nextIndex < items.size() && active.size() < parallelism) {
          final int index = nextIndex;
          nextIndex++;
          active.add(
              completions.submit(() -> new IndexedResult<>(index, task.execute(items.get(index)))));
        }
        final Future<IndexedResult<R>> finished = completions.take();
        active.remove(finished);
        final IndexedResult<R> result = finished.get();
        results.set(result.index(), result.value());
        completed++;
      }
      return results;
    } catch (final InterruptedException exception) {
      final boolean terminated = cancel.getAsBoolean();
      interrupt.run();
      final IOException failure =
          new IOException("Interrupted while executing parallel trimming tasks", exception);
      ParallelTrimFailures.addCancellationTimeout(failure, terminated);
      throw failure;
    } catch (final ExecutionException exception) {
      throw ParallelTrimFailures.executionFailure(exception, cancel);
    }
  }
}
