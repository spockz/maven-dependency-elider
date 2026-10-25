/* WHY: Verifies class loading log parsing without starting a JVM or depending on external trace
 * files. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.OriginEvidence;
import io.github.spockz.elider.model.TraceData;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers JVM class loading log file parsing. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class ClassLoaderLogReaderTest {
  /** Supplies isolated input paths for each test. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  ClassLoaderLogReaderTest() {}

  @Test
  void readsUnifiedLogAndRawClassNames() throws IOException {
    final Path log = tempDir.resolve("classes.log");
    Files.writeString(
        log,
        "[0.001s][info][class,load] java.lang.String source: jrt:/java.base\n"
            + "[info][class,load] org/example.Widget source: file:/app/classes/\n"
            + "org/example/RawName\n"
            + "[0.002s][info][class,load] com.example.Inner$Nested source: file:/app.jar\n"
            + "[warning][class,resolve] unrelated event\n");

    final TraceData result = new ClassLoaderLogReader().read(log);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder(
            "java.lang.String",
            "org.example.Widget",
            "org.example.RawName",
            "com.example.Inner$Nested");
    assertThat(result.loadedClassesSlashFormat())
        .contains("java/lang/String", "org/example/Widget");
  }

  @Test
  void detectsFormatsByContentAcrossSupportedSuffixes() throws IOException {
    final Path rawList = tempDir.resolve("classes.log");
    final Path redirectedLog = tempDir.resolve("classes.txt");
    Files.writeString(rawList, "org/example.RawLog\n");
    Files.writeString(
        redirectedLog, "[info][class,load] org.example.FromRedirect source: file:/app.jar\n");
    final ClassLoaderLogReader reader = new ClassLoaderLogReader();

    assertThat(reader.read(rawList).loadedClassesDotFormat()).containsExactly("org.example.RawLog");
    assertThat(reader.read(redirectedLog).loadedClassesDotFormat())
        .containsExactly("org.example.FromRedirect");
  }

  @Test
  void rejectsMalformedClassLoadEntries() throws IOException {
    final Path log = tempDir.resolve("malformed.log");
    Files.writeString(log, "[info][class,load] bad/ name source: file:/app.jar\n");

    assertThatIOException().isThrownBy(() -> new ClassLoaderLogReader().read(log));
  }

  @Test
  void rejectsNoiseOnlyLogsAndMalformedRawLists() throws IOException {
    final Path noise = tempDir.resolve("noise.log");
    final Path malformed = tempDir.resolve("malformed.txt");
    Files.writeString(noise, "application started\n[warning][class,resolve] unrelated event\n");
    Files.writeString(malformed, "java.lang.Object\norg/example/Needed Class\n");

    assertThatIOException().isThrownBy(() -> new ClassLoaderLogReader().read(noise));
    assertThatIOException().isThrownBy(() -> new ClassLoaderLogReader().read(malformed));
  }

  @Test
  void readsUnicodeAndSkipsHiddenClassEntries() throws IOException {
    final Path log = tempDir.resolve("hidden.log");
    Files.writeString(
        log,
        "[info][class,load] example.Éclair source: file:/app.jar\n"
            + "[info][class,load] java.util.ArrayDeque$$Lambda/0x00001234 source: file:/app.jar\n");

    final TraceData result = new ClassLoaderLogReader().read(log);

    assertThat(result.loadedClassesDotFormat()).containsExactly("example.Éclair");
  }

  @Test
  void preservesOnlyUnambiguousLocalJarOriginsAndDecodesUriEscapes() throws IOException {
    final Path log = tempDir.resolve("origins.log");
    final Path jarPath = tempDir.resolve("shared library.jar").toAbsolutePath().normalize();
    final String jarUri = jarPath.toUri().toASCIIString();
    Files.writeString(
        log,
        "[info][class,load] example.Known source: "
            + jarUri
            + "\n"
            + "[info][class,load] example.Directory source: file:/app/classes/\n"
            + "[info][class,load] example.Runtime source: jrt:/java.base\n"
            + "[info][class,load] example.Remote source: file://remote/app.jar\n"
            + "[info][class,load] example.Nested source: jar:file:/app.jar!/\n"
            + "[info][class,load] example.Ambiguous source: file:/one.jar source: file:/two.jar\n"
            + "[info][class,load] example.EmptyRepeated source: file:/one.jar source:\n"
            + "[info][class,load] example.TrailingGarbage source: file:/one.jar second.jar\n"
            + "[info][class,load] example.Relative source: file:relative.jar\n"
            + "[info][class,load] example.Malformed source: file:/bad%escape.jar\n"
            + "[info][class,load] example.MissingSource\n");

    final TraceData result = new ClassLoaderLogReader().read(log);

    assertThat(result.originsFor("example.Known"))
        .isEqualTo(new OriginEvidence(java.util.Set.of(jarPath), false));
    assertThat(result.originsFor("example.Directory")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Runtime")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Remote")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Nested")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Ambiguous")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.EmptyRepeated")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.TrailingGarbage")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Relative")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.Malformed")).isEqualTo(OriginEvidence.unknown());
    assertThat(result.originsFor("example.MissingSource")).isEqualTo(OriginEvidence.unknown());
  }

  @Test
  void reportsUnsupportedFileTypes() {
    final ClassLoaderLogReader reader = new ClassLoaderLogReader();

    assertThat(reader.supports(tempDir.resolve("classes.lst"))).isFalse();
    assertThatIOException().isThrownBy(() -> reader.read(tempDir.resolve("classes.lst")));
  }

  @Test
  void propagatesUnreadableFiles() {
    final Path missing = tempDir.resolve("missing.log");

    assertThatIOException().isThrownBy(() -> new ClassLoaderLogReader().read(missing));
  }
}
