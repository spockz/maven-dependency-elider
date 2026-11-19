/* WHY: Allows scoped tests to observe real MRJAR inspection and projection work. */

package io.github.spockz.elider.plugin;

import java.nio.file.Path;
import java.util.Objects;

/** Scoped observer for real MRJAR boundary events. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MultiReleaseWorkObserver {
  /** Active thread-inherited listener for the current test scope. */
  private static final ThreadLocal<Listener> CURRENT = new InheritableThreadLocal<>();

  private MultiReleaseWorkObserver() {}

  static Scope listen(final Listener listener) {
    Objects.requireNonNull(listener, "listener");
    final Listener previous = CURRENT.get();
    CURRENT.set(listener);
    return () -> {
      if (previous == null) {
        CURRENT.remove();
      } else {
        CURRENT.set(previous);
      }
    };
  }

  static void recordSourceInspected(final Path source) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onSourceInspected(source);
    }
  }

  static void recordDigestRead(final Path source) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onDigestRead(source);
    }
  }

  static void recordProjectionCreated(final Path source, final int release) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onProjectionCreated(source, release);
    }
  }

  /** Receives real MRJAR boundary events. */
  interface Listener {
    /** Called when an MRJAR source archive is inspected. */
    default void onSourceInspected(final Path source) {
      // Optional hook for scoped test observers.
    }

    /** Called when source digests are read outside shared SourceData. */
    default void onDigestRead(final Path source) {
      // Optional hook for scoped test observers.
    }

    /** Called when a target-release projection JAR is created. */
    default void onProjectionCreated(final Path source, final int release) {
      // Optional hook for scoped test observers.
    }
  }

  /** Restores the previous observer when closed. */
  @FunctionalInterface
  interface Scope extends AutoCloseable {
    @Override
    void close();
  }
}
