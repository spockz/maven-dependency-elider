// WHY: Captures Mojo summaries so tests can assert user-visible Maven log output.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;
import org.apache.maven.plugin.logging.Log;

/** Stores informational Mojo log lines and ignores other levels. */
@SuppressWarnings({"PMD.TooManyMethods", "PMD.UncommentedEmptyMethodBody"})
final class RecordingMavenLog implements Log {
  /** Rule key for package-private fixture API. */
  private static final String ACCESS_MODIFIER_SUPPRESSION = "PMD.CommentDefaultAccessModifier";

  /** Informational lines captured from the Mojo. */
  private final List<String> recordedMessages = new ArrayList<>();

  /** Warning lines captured from the Mojo. */
  private final List<String> recordedWarnings = new ArrayList<>();

  /** Debug lines captured by scenarios that assert proof abstention reasons. */
  private final List<String> recordedDebugMessages = new ArrayList<>();

  /** Whether this fixture exposes debug diagnostics to the behavior under test. */
  private final boolean debugEnabled;

  /** Creates a logger that records informational and warning messages only. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  RecordingMavenLog() {
    this(false);
  }

  /** Creates a logger with optional debug capture for refusal diagnostics. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  RecordingMavenLog(final boolean debugEnabled) {
    this.debugEnabled = debugEnabled;
  }

  /** Returns a stable copy of the captured messages. */
  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  List<String> messages() {
    return List.copyOf(recordedMessages);
  }

  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  List<String> warnings() {
    return List.copyOf(recordedWarnings);
  }

  @SuppressWarnings(ACCESS_MODIFIER_SUPPRESSION)
  List<String> debugMessages() {
    return List.copyOf(recordedDebugMessages);
  }

  @Override
  public boolean isDebugEnabled() {
    return debugEnabled;
  }

  @Override
  public void debug(final CharSequence content) {
    recordedDebugMessages.add(content.toString());
  }

  @Override
  public void debug(final CharSequence content, final Throwable error) {
    recordedDebugMessages.add(content.toString());
  }

  @Override
  public void debug(final Throwable error) {
    recordedDebugMessages.add(error.toString());
  }

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
