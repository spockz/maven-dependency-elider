/* WHY: Preserves task causes and cancellation timeout evidence. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.function.BooleanSupplier;

/** Preserves task causes and cancellation timeout evidence. */
final class ParallelTrimFailures {
  /** Bounds how long callers wait for interrupted workers to terminate. */
  /* package */ static final long CANCELLATION_GRACE_SECONDS = 30;

  private ParallelTrimFailures() {}

  /* package */ static IOException appendFailure(
      final IOException previous, final IOException next) {
    if (previous == null) {
      return next;
    }
    previous.addSuppressed(next);
    return previous;
  }

  /* package */ static IOException cancellationTimeoutFailure() {
    return new IOException(
        "Parallel trimming workers did not stop within "
            + CANCELLATION_GRACE_SECONDS
            + " seconds; running tasks were detached");
  }

  /* package */ static IOException parallelTaskFailure(final Throwable cause) {
    final String detail = cause.getMessage();
    return new IOException(
        detail == null
            ? "Parallel trimming task failed"
            : "Parallel trimming task failed: " + detail,
        cause);
  }

  /* package */ static IOException executionFailure(
      final ExecutionException exception, final BooleanSupplier cancel) {
    final Throwable cause = exception.getCause();
    if (cause instanceof Error error) {
      throw error;
    }
    final boolean terminated = cancel.getAsBoolean();
    final IOException failure = parallelTaskFailure(cause);
    addCancellationTimeout(failure, terminated);
    return failure;
  }

  /* package */ static void addCancellationTimeout(
      final Throwable failure, final boolean terminated) {
    if (!terminated) {
      failure.addSuppressed(cancellationTimeoutFailure());
    }
  }
}
