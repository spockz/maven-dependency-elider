/* WHY: Tests JFR extraction with locally compiled classes and a generated JFR recording. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import jdk.jfr.Event;
import jdk.jfr.Name;
import jdk.jfr.Recording;
import jdk.jfr.consumer.RecordedClass;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers JDK Flight Recorder class-load event extraction. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class JfrTraceReaderTest {
  /** Names the deliberately unrelated event recorded by the test. */
  private static final String UNRELATED_EVENT_NAME = "test.Unrelated";

  /** Names the JFR event used by the reader. */
  private static final String CLASS_LOAD_EVENT_NAME = "jdk.ClassLoad";

  /** Supplies a local destination for the generated recording. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  JfrTraceReaderTest() {}

  @Test
  void readsOnlyClassLoadEventsAndOmitsHiddenOrAbsentClasses() throws Exception {
    final String loadedName = "example.generated.LoadedDuringRecording";
    final Path classesDir = tempDir.resolve("classes");
    compileClass(classesDir, "example.generated", "LoadedDuringRecording");
    compileClass(classesDir, "io.github.spockz.elider.trace", "HiddenFixture");
    final Path recordingPath = tempDir.resolve("classes.jfr");

    try (Recording recording = new Recording()) {
      recording.enable("jdk.ClassLoad");
      recording.enable("test.Unrelated");
      recording.start();
      try (URLClassLoader loader =
          new URLClassLoader(
              new java.net.URL[] {classesDir.toUri().toURL()},
              Thread.currentThread().getContextClassLoader())) {
        Class.forName(loadedName, true, loader);
      }
      final Path hiddenClass =
          classesDir.resolve("io/github/spockz/elider/trace/HiddenFixture.class");
      MethodHandles.lookup().defineHiddenClass(Files.readAllBytes(hiddenClass), true);
      new UnrelatedEvent().commit();
      recording.stop();
      recording.dump(recordingPath);
    }

    final Set<String> recordedClassNames = recordedClassNames(recordingPath);
    assertThat(hasUnrelatedEvent(recordingPath)).isTrue();
    assertThat(recordedClassNames).anyMatch(name -> name.contains("HiddenFixture"));
    final TraceData result = new JfrTraceReader().read(recordingPath);

    assertThat(result.loadedClassesDotFormat()).contains(loadedName);
    assertThat(result.loadedClassesSlashFormat())
        .contains("example/generated/LoadedDuringRecording");
    assertThat(result.loadedClassesDotFormat()).noneMatch(name -> name.contains("HiddenFixture"));
  }

  @Test
  void rejectsUnsupportedAndUnreadableFiles() {
    final JfrTraceReader reader = new JfrTraceReader();
    final Path unsupported = tempDir.resolve("classes.log");

    assertThat(reader.supports(unsupported)).isFalse();
    assertThatIOException().isThrownBy(() -> reader.read(unsupported));
    assertThatIOException().isThrownBy(() -> reader.read(tempDir.resolve("missing.jfr")));
  }

  private void compileClass(final Path output, final String packageName, final String className)
      throws IOException {
    final Path source =
        tempDir
            .resolve("source")
            .resolve(packageName.replace('.', '/'))
            .resolve(className + ".java");
    Files.createDirectories(source.getParent());
    Files.createDirectories(output);
    Files.writeString(source, "package " + packageName + "; public class " + className + " {}");
    io.github.spockz.elider.test.CompilationFixtureSupport.compile(output, List.of(source));
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static boolean hasUnrelatedEvent(final Path recordingPath) throws IOException {
    try (RecordingFile file = new RecordingFile(recordingPath)) {
      while (file.hasMoreEvents()) {
        final RecordedEvent event = file.readEvent();
        if (UNRELATED_EVENT_NAME.equals(event.getEventType().getName())) {
          return true;
        }
      }
    }
    return false;
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  private static Set<String> recordedClassNames(final Path recordingPath) throws IOException {
    final Set<String> names = new HashSet<>();
    try (RecordingFile file = new RecordingFile(recordingPath)) {
      while (file.hasMoreEvents()) {
        final RecordedEvent event = file.readEvent();
        if (CLASS_LOAD_EVENT_NAME.equals(event.getEventType().getName())) {
          final RecordedClass loadedClass = event.getClass("loadedClass");
          if (loadedClass != null) {
            names.add(loadedClass.getName());
          }
        }
      }
    }
    return names;
  }

  /** Represents an unrelated JFR event that the class-load reader must skip. */
  @Name("test.Unrelated")
  static final class UnrelatedEvent extends Event {}
}
