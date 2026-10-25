/* WHY: Verifies JaCoCo binary parsing, class aggregation, and malformed-input failures. */

package io.github.spockz.elider.trace;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIOException;

import io.github.spockz.elider.model.TraceData;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataReader;
import org.jacoco.core.data.ExecutionDataWriter;
import org.jacoco.core.data.IncompatibleExecDataVersionException;
import org.jacoco.core.data.SessionInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers JaCoCo execution data records and invalid binary files. */
@SuppressWarnings({
  "PMD.UnitTestContainsTooManyAsserts",
  "PMD.UncommentedEmptyConstructor",
  "PMD.CommentDefaultAccessModifier"
})
class JaCoCoTraceReaderTest {
  /** Supplies isolated files for the tests. */
  @TempDir Path tempDir;

  /** Creates a package-visible test instance for JUnit. */
  JaCoCoTraceReaderTest() {}

  @Test
  void readsRecordsRegardlessOfProbeHitsAndDeduplicatesAcrossSessions() throws IOException {
    final Path exec = tempDir.resolve("coverage.exec");
    writeExec(
        exec,
        writer -> {
          writer.visitSessionInfo(new SessionInfo("one", 1, 2));
          writer.visitClassExecution(
              new ExecutionData(11, "org/example/Hit", new boolean[] {true}));
          writer.visitClassExecution(
              new ExecutionData(13, "org/example/Duplicate", new boolean[] {true, false}));
          writer.visitSessionInfo(new SessionInfo("two", 3, 4));
          writer.visitClassExecution(
              new ExecutionData(13, "org/example/Duplicate", new boolean[] {false, true}));
        });

    assertThat(classRecordCount(exec)).isEqualTo(3);
    final TraceData result = new JaCoCoTraceReader().read(exec);

    assertThat(result.loadedClassesDotFormat())
        .containsExactlyInAnyOrder("org.example.Hit", "org.example.Duplicate");
  }

  @Test
  void includesClassRecordWithNoHitProbe() throws IOException {
    final Path exec = tempDir.resolve("unhit.exec");
    writeExec(
        exec,
        writer ->
            writer.visitClassExecution(
                new ExecutionData(15, "org/example/Unhit", new boolean[] {true})));
    final byte[] encoded = Files.readAllBytes(exec);
    encoded[encoded.length - 1] = 0;
    Files.write(exec, encoded);

    assertThat(classRecordCount(exec)).isEqualTo(1);
    assertThat(new JaCoCoTraceReader().read(exec).loadedClassesDotFormat())
        .containsExactly("org.example.Unhit");
  }

  @Test
  void rejectsMismatchedProbeCountsAndInvalidNamesButAcceptsUnicode() throws IOException {
    final Path incompatible = tempDir.resolve("probe-count.exec");
    writeExec(
        incompatible,
        writer -> {
          writer.visitClassExecution(
              new ExecutionData(16, "org/example/Changed", new boolean[] {true}));
          writer.visitClassExecution(
              new ExecutionData(16, "org/example/Changed", new boolean[] {true, false}));
        });
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(incompatible));

    final Path invalid = tempDir.resolve("invalid-name.exec");
    writeExec(
        invalid,
        writer ->
            writer.visitClassExecution(new ExecutionData(17, "bad-name", new boolean[] {true})));
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(invalid));

    final Path emptyName = tempDir.resolve("empty-name.exec");
    writeExec(
        emptyName,
        writer -> writer.visitClassExecution(new ExecutionData(19, "", new boolean[] {true})));
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(emptyName));

    final Path unicode = tempDir.resolve("unicode.exec");
    writeExec(
        unicode,
        writer ->
            writer.visitClassExecution(
                new ExecutionData(18, "org/example/例子/Ünicode", new boolean[] {true})));
    assertThat(new JaCoCoTraceReader().read(unicode).loadedClassesDotFormat())
        .containsExactly("org.example.例子.Ünicode");
  }

  @Test
  void acceptsSessionOnlyFilesAsEmptyTraces() throws IOException {
    final Path exec = tempDir.resolve("session.exec");
    writeExec(exec, writer -> writer.visitSessionInfo(new SessionInfo("only", 1, 2)));

    assertThat(new JaCoCoTraceReader().read(exec)).isEqualTo(TraceData.empty());
    assertThatIOException().isThrownBy(() -> new CompositeTraceReader().readAll(List.of(exec)));
  }

  @Test
  void rejectsEmptyCorruptIncompatibleTruncatedAndConflictingFiles() throws IOException {
    final Path empty = tempDir.resolve("empty.exec");
    Files.write(empty, new byte[0]);
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(empty));

    final Path corrupt = tempDir.resolve("corrupt.exec");
    Files.write(corrupt, new byte[] {0, 0, 0, 0});
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(corrupt));

    final Path incompatible = tempDir.resolve("incompatible.exec");
    final byte[] header = ExecutionDataWriter.getFileHeader();
    header[header.length - 2] = 0x7f;
    header[header.length - 1] = 0x7f;
    Files.write(incompatible, header);
    assertThatIOException()
        .isThrownBy(() -> new JaCoCoTraceReader().read(incompatible))
        .withCauseInstanceOf(IncompatibleExecDataVersionException.class);

    final Path truncated = tempDir.resolve("truncated.exec");
    Files.write(truncated, new byte[] {(byte) 0x01, (byte) 0xc0});
    assertThatIOException().isThrownBy(() -> new JaCoCoTraceReader().read(truncated));

    final Path validThenTruncated = tempDir.resolve("valid-then-truncated.exec");
    writeExec(
        validThenTruncated,
        writer ->
            writer.visitClassExecution(
                new ExecutionData(20, "org/example/BeforeTruncation", new boolean[] {true})));
    assertThat(classRecordCount(validThenTruncated)).isEqualTo(1);
    final Path secondRecord = tempDir.resolve("truncated-second-record.exec");
    writeExec(
        secondRecord,
        writer ->
            writer.visitClassExecution(
                new ExecutionData(22, "org/example/Truncated", new boolean[] {true})));
    final byte[] secondRecordBytes = Files.readAllBytes(secondRecord);
    final int headerLength = ExecutionDataWriter.getFileHeader().length;
    final byte[] truncatedBlock =
        Arrays.copyOfRange(secondRecordBytes, headerLength, secondRecordBytes.length - 1);
    Files.write(validThenTruncated, truncatedBlock, StandardOpenOption.APPEND);
    assertThatIOException()
        .isThrownBy(() -> new JaCoCoTraceReader().read(validThenTruncated))
        .withCauseInstanceOf(IOException.class);

    final Path conflict = tempDir.resolve("conflict.exec");
    writeExec(
        conflict,
        writer -> {
          writer.visitClassExecution(
              new ExecutionData(21, "org/example/Conflict", new boolean[] {true}));
          writer.visitClassExecution(
              new ExecutionData(21, "org/example/Different", new boolean[] {true}));
        });
    assertThat(classRecordCount(conflict)).isEqualTo(2);
    assertThatIOException()
        .isThrownBy(() -> new JaCoCoTraceReader().read(conflict))
        .withCauseInstanceOf(IllegalStateException.class);
  }

  @Test
  void compositeDispatchesAndMergesJaCoCoFiles() throws IOException {
    final Path exec = tempDir.resolve("coverage.exec");
    final Path log = tempDir.resolve("classes.log");
    writeExec(
        exec,
        writer ->
            writer.visitClassExecution(
                new ExecutionData(31, "org/example/Covered", new boolean[] {true})));
    Files.writeString(log, "[info][class,load] org.example.Loaded source: file:/app.jar\n");
    final CompositeTraceReader reader = new CompositeTraceReader();

    assertThat(reader.supports(exec)).isTrue();
    assertThat(reader.readAll(List.of(exec, log)).loadedClassesDotFormat())
        .containsExactlyInAnyOrder("org.example.Covered", "org.example.Loaded");
  }

  private static void writeExec(final Path path, final Consumer<ExecutionDataWriter> action)
      throws IOException {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    final ExecutionDataWriter writer = new ExecutionDataWriter(bytes);
    action.accept(writer);
    Files.write(path, bytes.toByteArray());
  }

  private static int classRecordCount(final Path path) throws IOException {
    final List<ExecutionData> records = new ArrayList<>();
    try (InputStream input = Files.newInputStream(path)) {
      final ExecutionDataReader reader = new ExecutionDataReader(input);
      reader.setSessionInfoVisitor(sessionInfo -> {});
      reader.setExecutionDataVisitor(records::add);
      reader.read();
    }
    return records.size();
  }
}
