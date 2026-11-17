/* WHY: Verifies one captured production snapshot feeds all evidence passes and its guard digest. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** WHY: One captured class inventory feeds all production evidence passes. */
final class ProductionBytecodeAnalysisTest {
  /** ASM owner used by the cross-class constant fixture. */
  private static final String SERVICE_LOADER = "java/util/ServiceLoader";

  /** WHY: Fixture roots share one package identity. */
  private static final String SAMPLE_PACKAGE = "sample";

  /** Isolated output root for each test case. */
  @TempDir private Path temporaryDirectory;

  /** Allows JUnit to inject the temporary directory after construction. */
  /* package */ ProductionBytecodeAnalysisTest() {
    // JUnit injects @TempDir fields after constructing the test.
  }

  @Test
  void analyzesOneSnapshotAndResolvesCrossClassServiceConstants() throws IOException {
    final Path output = Files.createDirectory(temporaryDirectory.resolve("classes"));
    final Path packageDirectory = Files.createDirectory(output.resolve(SAMPLE_PACKAGE));
    Files.write(packageDirectory.resolve("App.class"), appClass(SAMPLE_PACKAGE + "/App"));
    final ProductionBytecodeAnalysis.Snapshot snapshot = ProductionBytecodeAnalysis.capture(output);
    final BytecodeReferenceScan references = snapshot.bytecodeReferences();
    final Set<String> directReferences = references.referencedClasses();
    final int classFilesScanned = references.classFilesScanned();

    assertAll(
        () ->
            assertThat(snapshot.fingerprint())
                .isEqualTo(ProductionBytecodeAnalysis.capture(output).fingerprint()),
        () -> assertThat(directReferences).contains(SAMPLE_PACKAGE + ".Base"),
        () -> assertThat(classFilesScanned).isEqualTo(1),
        () -> assertThat(snapshot.classNames()).containsExactly(SAMPLE_PACKAGE + ".App"),
        () -> assertThat(snapshot.scanServiceLoaderCalls().provenServiceInterfaces()).isEmpty(),
        () ->
            assertThat(scanCrossClassServiceConstants().provenServiceInterfaces())
                .containsExactly("com.example.CrossService"),
        () -> {
          Files.write(packageDirectory.resolve("Other.class"), appClass("sample/Other"));
          assertThat(ProductionBytecodeAnalysis.capture(output).fingerprint())
              .isNotEqualTo(snapshot.fingerprint());
        });
  }

  @Test
  void capturesClassesAcrossAdditionalRoots() throws IOException {
    final Path mainOutput = Files.createDirectory(temporaryDirectory.resolve("main-classes"));
    final Path aotOutput = Files.createDirectory(temporaryDirectory.resolve("aot-classes"));
    final Path mainPkg = Files.createDirectory(mainOutput.resolve(SAMPLE_PACKAGE));
    final Path aotPkg = Files.createDirectory(aotOutput.resolve(SAMPLE_PACKAGE));
    Files.write(mainPkg.resolve("MainApp.class"), appClass(SAMPLE_PACKAGE + "/MainApp"));
    Files.write(aotPkg.resolve("AotGenerated.class"), appClass(SAMPLE_PACKAGE + "/AotGenerated"));

    final ProductionBytecodeAnalysis.Snapshot snapshot =
        ProductionBytecodeAnalysis.capture(mainOutput, List.of(aotOutput));

    assertAll(
        () ->
            assertThat(snapshot.classNames())
                .containsExactlyInAnyOrder(
                    SAMPLE_PACKAGE + ".MainApp", SAMPLE_PACKAGE + ".AotGenerated"),
        () -> assertThat(snapshot.bytecodeReferences().classFilesScanned()).isEqualTo(2),
        () ->
            assertThat(snapshot.fingerprint())
                .isEqualTo(
                    ProductionBytecodeAnalysis.capture(mainOutput, List.of(aotOutput))
                        .fingerprint()));
  }

  @Test
  void missingOutputForProjectWithoutSourcesIsEmpty() throws IOException {
    final Path output = temporaryDirectory.resolve("no-production-output");

    final ProductionBytecodeAnalysis.Snapshot snapshot = ProductionBytecodeAnalysis.capture(output);
    final BytecodeReferenceScan references = snapshot.bytecodeReferences();
    final boolean complete = references.complete();
    final int classFilesScanned = references.classFilesScanned();
    final Set<String> directReferences = references.referencedClasses();

    assertAll(
        () -> assertTrue(complete, "a missing output is a complete empty snapshot"),
        () ->
            org.junit.jupiter.api.Assertions.assertEquals(
                0, classFilesScanned, "missing output has no class files"),
        () -> assertThat(directReferences).isEmpty(),
        () -> assertThat(snapshot.classNames()).isEmpty());
  }

  @Test
  void missingPrimaryKeepsAdditionalOutputAndFingerprint() throws IOException {
    final Path output = temporaryDirectory.resolve("missing-primary");
    final Path aotOutput = Files.createDirectory(temporaryDirectory.resolve("aot-only"));
    final Path packageDirectory = Files.createDirectory(aotOutput.resolve("sample"));
    Files.write(packageDirectory.resolve("AotGenerated.class"), appClass("sample/AotGenerated"));

    final ProductionBytecodeAnalysis.Snapshot snapshot =
        ProductionBytecodeAnalysis.capture(output, List.of(aotOutput));

    assertAll(
        () -> assertThat(snapshot.bytecodeReferences().classFilesScanned()).isEqualTo(1),
        () -> assertThat(snapshot.classNames()).containsExactly("sample.AotGenerated"),
        () ->
            assertThat(snapshot.fingerprint())
                .isEqualTo(
                    ProductionBytecodeAnalysis.capture(output, List.of(aotOutput)).fingerprint()));
  }

  @Test
  void presentNonDirectoryPrimaryStillFails() throws IOException {
    final Path output = temporaryDirectory.resolve("not-a-directory");
    Files.writeString(output, "not a directory");

    assertThatThrownBy(() -> ProductionBytecodeAnalysis.capture(output))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Production class output path is not a directory");
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
