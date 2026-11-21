/* WHY: Shares scoped observations at real archive I/O boundaries across core and plugin stages. */

package io.github.spockz.elider.io;

import java.nio.file.Path;
import java.util.Objects;

/** Observes archive work on the current thread and its newly created workers. */
public final class ArchiveWorkObserver {
  /** Active listener inherited by workers created within this scope. */
  private static final ThreadLocal<Listener> CURRENT = new InheritableThreadLocal<>();

  private ArchiveWorkObserver() {}

  /** Installs a listener until the returned scope restores its predecessor. */
  public static Scope listen(final Listener listener) {
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

  /** Records an attempted physical elevation-plan inventory read. */
  public static void recordSourceInspected(final Path source) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onSourceInspected(source);
    }
  }

  /** Records an attempted file read for digest computation. */
  public static void recordDigestRead(final Path source) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onDigestRead(source);
    }
  }

  /** Records an attempted effective-release projection. */
  public static void recordProjectionCreated(final Path source, final int release) {
    final Listener listener = CURRENT.get();
    if (listener != null) {
      listener.onProjectionCreated(source, release);
    }
  }

  /** Receives selected operation attempts; unimplemented callbacks do nothing. */
  @SuppressWarnings("PMD.UncommentedEmptyMethodBody")
  public interface Listener {
    /** Called when a physical elevation-plan inventory is read. */
    default void onSourceInspected(final Path source) {}

    /** Called when a file is read for digest computation. */
    default void onDigestRead(final Path source) {}

    /** Called when a target-release projection JAR is created. */
    default void onProjectionCreated(final Path source, final int release) {}
  }

  /** Restores the previous observer when closed. */
  @FunctionalInterface
  public interface Scope extends AutoCloseable {
    @Override
    void close();
  }
}
