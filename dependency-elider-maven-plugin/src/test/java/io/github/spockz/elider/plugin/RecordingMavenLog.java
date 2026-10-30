// WHY: Captures Mojo summaries so tests can assert user-visible Maven log output.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.logging.Log;

/** Stores informational Mojo log lines and ignores other levels. */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.UncommentedEmptyMethodBody"})
final class RecordingMavenLog implements Log {
  /** Informational lines captured from the Mojo. */
  private final List<String> recordedMessages = new ArrayList<>();

  /** Warning lines captured from the Mojo. */
  private final List<String> recordedWarnings = new ArrayList<>();

  /** Creates an empty logger for an isolated test. */
  @SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UncommentedEmptyConstructor"})
  RecordingMavenLog() {}

  /** Returns a stable copy of the captured messages. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  List<String> messages() {
    return List.copyOf(recordedMessages);
  }

  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  List<String> warnings() {
    return List.copyOf(recordedWarnings);
  }

  @Override
  public boolean isDebugEnabled() {
    return false;
  }

  @Override
  public void debug(final CharSequence content) {}

  @Override
  public void debug(final CharSequence content, final Throwable error) {}

  @Override
  public void debug(final Throwable error) {}

  @Override
  public boolean isInfoEnabled() {
    return true;
  }

  @Override
  public void info(final CharSequence content) {
    recordedMessages.add(content.toString());
  }

  @Override
  public void info(final CharSequence content, final Throwable error) {
    recordedMessages.add(content.toString());
  }

  @Override
  public void info(final Throwable error) {
    recordedMessages.add(error.toString());
  }

  @Override
  public boolean isWarnEnabled() {
    return true;
  }

  @Override
  public void warn(final CharSequence content) {
    recordedWarnings.add(content.toString());
  }

  @Override
  public void warn(final CharSequence content, final Throwable error) {
    recordedWarnings.add(content.toString());
  }

  @Override
  public void warn(final Throwable error) {
    recordedWarnings.add(error.toString());
  }

  @Override
  public boolean isErrorEnabled() {
    return false;
  }

  @Override
  public void error(final CharSequence content) {}

  @Override
  public void error(final CharSequence content, final Throwable error) {}

  @Override
  public void error(final Throwable error) {}
}
