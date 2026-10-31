/* WHY: Verifies consumed descriptor snapshots reject changed bytes, targets, and malformed
 * classdata. This focused location keeps file mutation cases independent of parsing fixtures.
 */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Verifies consumed descriptor snapshots and predefined classdata validation. */
/* package */ final class NativeImageConsumedInputSnapshotTest {
  /** Stable hash used by the predefined classdata fixtures. */
  private static final String PREDEFINED_HASH = "fedcba9876543210fedcba9876543210";

  /** Temporary directory for descriptor snapshots and classdata. */
  /* package */ @TempDir Path inputDirectory;

  /** Creates this focused test class. */
  /* package */ NativeImageConsumedInputSnapshotTest() {
    // JUnit constructs this test group directly.
  }

  /** Rejects same-size descriptor edits with restored modification times. */
  /* package */
  @Test
  @DisplayName("ADR-0009/consumed descriptor bytes remain bound to preparation")
  void contentChangesWithPreservedSizeAndMtimeInvalidateSnapshot() throws IOException {
    final Path descriptor = inputDirectory.resolve("same-size.payload");
    Files.writeString(descriptor, "[1,2,3]");
    final NativeImageInput input =
        NativeImageInput.file(descriptor, NativeImageDescriptorKind.REFLECTION);
    input.open().close();
    final NativeImageConsumedInput snapshot = input.consumedInputs().get(0);
    final FileTime originalTime = Files.getLastModifiedTime(descriptor);
    Files.writeString(descriptor, "[1,2,4]");
    Files.setLastModifiedTime(descriptor, originalTime);

    assertThatThrownBy(() -> NativeImageConsumedInput.verifyAll(List.of(snapshot)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("content changed");
  }

  /** Rejects symlink retargeting to byte-identical content. */
  /* package */
  @Test
  @DisplayName("ADR-0009/consumed symlink target remains bound to preparation")
  void symlinkRetargetToEqualBytesInvalidatesSnapshot() throws IOException {
    final Path firstTarget = inputDirectory.resolve("first-target.payload");
    final Path secondTarget = inputDirectory.resolve("second-target.payload");
    final Path logicalPath = inputDirectory.resolve("linked.payload");
    Files.writeString(firstTarget, "same");
    Files.writeString(secondTarget, "same");
    Files.createSymbolicLink(logicalPath, firstTarget.getFileName());
    final NativeImageInput input =
        NativeImageInput.file(logicalPath, NativeImageDescriptorKind.REFLECTION);
    input.open().close();
    final NativeImageConsumedInput snapshot = input.consumedInputs().get(0);
    Files.delete(logicalPath);
    Files.createSymbolicLink(logicalPath, secondTarget.getFileName());

    assertThatThrownBy(() -> NativeImageConsumedInput.verifyAll(List.of(snapshot)))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("target changed");
  }

  /** Confirms valid predefined classdata reaches ASM and yields its references. */
  /* package */
  @Test
  @DisplayName("ADR-0009/valid predefined classdata extracts types")
  void validPredefinedClassdataExtractsTypes() throws IOException {
    final NativeImageInput input = predefinedInput(classData());

    assertThat(NativeImagePredefinedBytecode.read(input, PREDEFINED_HASH))
        .contains("org.example.Truncated", "java.lang.Object");
  }

  /** Rejects malformed classdata headers with hash and descriptor context. */
  /* package */
  @Test
  @DisplayName("ADR-0009/malformed predefined classdata headers fail with context")
  void malformedPredefinedClassdataHeadersFailWithContext() throws IOException {
    for (final byte[] malformed :
        List.of(
            new byte[0],
            new byte[] {(byte) 0xca, (byte) 0xfe, (byte) 0xba, (byte) 0xbe, 0, 0, 0, 61})) {
      final NativeImageInput input = predefinedInput(malformed);
      assertThatThrownBy(() -> NativeImagePredefinedBytecode.read(input, PREDEFINED_HASH))
          .isInstanceOf(IOException.class)
          .hasMessageContaining(PREDEFINED_HASH)
          .hasMessageContaining("malformed-predefined.payload");
    }
  }

  /** Proves truncated bytes beyond the header reach and fail inside the ASM parser. */
  /* package */
  @Test
  @DisplayName("ADR-0009/truncated predefined classdata fails inside the parser")
  void truncatedPredefinedClassdataFailsInsideParser() throws IOException {
    final byte[] validClassData = classData();
    final NativeImageInput input =
        predefinedInput(Arrays.copyOf(validClassData, validClassData.length - 1));

    assertThatThrownBy(() -> NativeImagePredefinedBytecode.read(input, PREDEFINED_HASH))
        .isInstanceOf(IOException.class)
        .hasMessageContaining(PREDEFINED_HASH)
        .hasMessageContaining("malformed-predefined.payload")
        .hasCauseInstanceOf(ArrayIndexOutOfBoundsException.class);
  }

  private NativeImageInput predefinedInput(final byte[] classdata) throws IOException {
    final Path descriptor = inputDirectory.resolve("malformed-predefined.payload");
    Files.writeString(descriptor, "[]");
    final Path siblingDirectory =
        Files.createDirectories(inputDirectory.resolve("agent-extracted-predefined-classes"));
    Files.write(siblingDirectory.resolve(PREDEFINED_HASH + ".classdata"), classdata);
    return NativeImageInput.file(descriptor, NativeImageDescriptorKind.PREDEFINED_CLASSES);
  }

  private static byte[] classData() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "org/example/Truncated", null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }
}
