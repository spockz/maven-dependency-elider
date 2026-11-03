/* WHY: Verifies one captured production snapshot feeds all evidence passes and its guard digest. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Covers shared production bytecode capture. */
final class ProductionBytecodeAnalysisTest {
  /** ASM owner used by the cross-class constant fixture. */
  private static final String SERVICE_LOADER = "java/util/ServiceLoader";

  /** Isolated output root for each test case. */
  @TempDir private Path temporaryDirectory;

  /** Allows JUnit to inject the temporary directory after construction. */
  /* package */ ProductionBytecodeAnalysisTest() {
    // JUnit injects @TempDir fields after constructing the test.
  }

  @Test
  void analyzesOneSnapshotAndResolvesCrossClassServiceConstants() throws IOException {
    final Path output = Files.createDirectory(temporaryDirectory.resolve("classes"));
    final Path packageDirectory = Files.createDirectory(output.resolve("sample"));
    Files.write(packageDirectory.resolve("App.class"), appClass("sample/App"));
    final ProductionBytecodeAnalysis.Snapshot snapshot = ProductionBytecodeAnalysis.capture(output);

    assertAll(
        () ->
            assertThat(snapshot.fingerprint())
                .isEqualTo(ProductionBytecodeAnalysis.fingerprint(output)),
        () -> assertThat(snapshot.bytecodeReferences().referencedClasses()).contains("sample.Base"),
        () -> assertThat(snapshot.bytecodeReferences().classFilesScanned()).isEqualTo(1),
        () -> assertThat(snapshot.classNames()).containsExactly("sample.App"),
        () -> assertThat(snapshot.scanServiceLoaderCalls().provenServiceInterfaces()).isEmpty(),
        () ->
            assertThat(scanCrossClassServiceConstants().provenServiceInterfaces())
                .containsExactly("com.example.CrossService"),
        () -> {
          Files.write(packageDirectory.resolve("Other.class"), appClass("sample/Other"));
          assertThat(ProductionBytecodeAnalysis.fingerprint(output))
              .isNotEqualTo(snapshot.fingerprint());
        });
  }

  @Test
  void capturesClassesAcrossAdditionalRoots() throws IOException {
    final Path mainOutput = Files.createDirectory(temporaryDirectory.resolve("main-classes"));
    final Path aotOutput = Files.createDirectory(temporaryDirectory.resolve("aot-classes"));
    final Path mainPkg = Files.createDirectory(mainOutput.resolve("sample"));
    final Path aotPkg = Files.createDirectory(aotOutput.resolve("sample"));
    Files.write(mainPkg.resolve("MainApp.class"), appClass("sample/MainApp"));
    Files.write(aotPkg.resolve("AotGenerated.class"), appClass("sample/AotGenerated"));

    final ProductionBytecodeAnalysis.Snapshot snapshot =
        ProductionBytecodeAnalysis.capture(mainOutput, List.of(aotOutput));

    assertAll(
        () ->
            assertThat(snapshot.classNames())
                .containsExactlyInAnyOrder("sample.MainApp", "sample.AotGenerated"),
        () -> assertThat(snapshot.bytecodeReferences().classFilesScanned()).isEqualTo(2),
        () ->
            assertThat(snapshot.fingerprint())
                .isEqualTo(ProductionBytecodeAnalysis.fingerprint(mainOutput, List.of(aotOutput))));
  }

  @Test
  void rejectsSymbolicLinksInProductionOutput() throws IOException {
    final Path output = Files.createDirectory(temporaryDirectory.resolve("linked-classes"));
    try {
      Files.createSymbolicLink(output.resolve("Alias.class"), Path.of("Target.class"));
    } catch (final IOException | UnsupportedOperationException exception) {
      Assumptions.assumeTrue(false, "Filesystem cannot create symbolic links: " + exception);
    }

    assertThatThrownBy(() -> ProductionBytecodeAnalysis.capture(output))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Symbolic link in production class output");
  }

  private static ServiceLoaderCallScanner.ScanResult scanCrossClassServiceConstants()
      throws IOException {
    return ServiceLoaderCallScanner.scanCaptured(
        List.of(
            new ProductionBytecodeAnalysis.ClassFile(Path.of("AConsumer.class"), consumerClass()),
            new ProductionBytecodeAnalysis.ClassFile(Path.of("ZProvider.class"), providerClass())));
  }

  private static byte[] consumerClass() {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/Consumer", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "load", "()V", null, null);
    method.visitCode();
    method.visitFieldInsn(Opcodes.GETSTATIC, "sample/Provider", "SERVICE", "Ljava/lang/String;");
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER,
        "load",
        "(Ljava/lang/String;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] providerClass() {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/Provider", null, "java/lang/Object", null);
    writer
        .visitField(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
            "SERVICE",
            "Ljava/lang/String;",
            null,
            "com.example.CrossService")
        .visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] appClass(final String name) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "sample/Base", null);
    writer.visitEnd();
    return writer.toByteArray();
  }
}
