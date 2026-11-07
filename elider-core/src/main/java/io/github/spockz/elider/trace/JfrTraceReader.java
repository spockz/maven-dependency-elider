/* WHY: Extracts loaded classes from JFR recordings for shared reachability analysis. */

package io.github.spockz.elider.trace;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import jdk.jfr.consumer.RecordedClass;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;

/** Reads loaded classes from JDK Flight Recorder {@code jdk.ClassLoad} events. */
public final class JfrTraceReader implements RuntimeTraceReader {
  /** JFR event carrying class-load observations. */
  private static final String CLASS_LOAD_EVENT = "jdk.ClassLoad";

  /** JFR event indicating incomplete recording data. */
  private static final String DATA_LOSS_EVENT = "jdk.DataLoss";

  /** Sentinel amount for events without data-loss accounting. */
  private static final long NO_DATA_LOSS = 0L;

  /** Creates the public reader implementation used by runtime evidence clients. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JfrTraceReader() {}

  @Override
  public TraceEvidenceKind evidenceKind() {
    return TraceEvidenceKind.JFR_CLASS_LOAD;
  }

  /** Recognizes JFR files by their conventional {@code .jfr} suffix. */
  @Override
  public boolean supports(final Path path) {
    final String fileName = supportedFileName(path);
    return fileName != null && fileName.endsWith(".jfr");
  }

  /** Reads {@code jdk.ClassLoad} events and omits absent or hidden classes. */
  @Override
  @SuppressWarnings("PMD.LawOfDemeter")
  public TraceData read(final Path path) throws IOException {
    if (!supports(path)) {
      throw new IOException("Unsupported JFR recording file: " + path);
    }
    final Set<String> classes = new HashSet<>();
    try (RecordingFile recording = new RecordingFile(path)) {
      while (recording.hasMoreEvents()) {
        final RecordedEvent event = recording.readEvent();
        final String eventTypeName = event.getEventType().getName();
        if (DATA_LOSS_EVENT.equals(eventTypeName)) {
          acceptEvent(eventTypeName, null, event.getLong("amount"), classes);
        } else if (CLASS_LOAD_EVENT.equals(eventTypeName)) {
          final RecordedClass loadedClass = event.getClass("loadedClass");
          acceptEvent(
              eventTypeName,
              loadedClass == null ? null : loadedClass.getName(),
              NO_DATA_LOSS,
              classes);
        }
      }
    }
    return TraceData.of(classes);
  }

  /* default */ static void acceptEvent(
      final String eventTypeName,
      final String loadedClassName,
      final long dataLossAmount,
      final Set<String> classes)
      throws IOException {
    if (DATA_LOSS_EVENT.equals(eventTypeName)) {
      if (dataLossAmount > NO_DATA_LOSS) {
        throw new IOException("JFR recording reports lost data: " + dataLossAmount + " bytes");
      }
    } else if (CLASS_LOAD_EVENT.equals(eventTypeName)) {
      addLoadedClassName(loadedClassName, classes);
    }
  }

  private static void addLoadedClassName(final String className, final Set<String> classes) {
    if (className != null && !TraceClassName.isHidden(className)) {
      classes.add(className);
    }
  }

  private static String supportedFileName(final Path path) {
    if (path == null) {
      return null;
    }
    final Path fileName = path.getFileName();
    if (fileName == null) {
      return null;
    }
    return fileName.toString().toLowerCase(Locale.ROOT);
  }
}
