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
  /** Creates a reader for JFR recording files. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JfrTraceReader() {}

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
        if (!"jdk.ClassLoad".equals(eventTypeName)) {
          continue;
        }
        final RecordedClass loadedClass = event.getClass("loadedClass");
        addLoadedClassName(loadedClass == null ? null : loadedClass.getName(), classes);
      }
    }
    return TraceData.of(classes);
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
