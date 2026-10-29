/* WHY: Verifies that ServiceLoader call scanning extracts constant service targets from bytecode
 * while ignoring non-constant or unprovable dynamic service lookups. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Tests for ServiceLoader call scanning. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.AvoidDuplicateLiterals",
  "PMD.AtLeastOneConstructor"
})
class ServiceLoaderCallScannerTest {
  private static final String SERVICE_LOADER_INTERNAL = "java/util/ServiceLoader";
  private static final String NO_ARG_VOID = "()V";

  @TempDir Path tempDir;

  @Test
  void detectsDirectClassConstantArgument() throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/DirectApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "loadService", NO_ARG_VOID, null, null);
    method.visitCode();
    method.visitLdcInsn(Type.getObjectType("com/example/DirectService"));
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "load",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result =
        scanner.scan(new ByteArrayInputStream(writer.toByteArray()));

    assertThat(result.provenServiceInterfaces()).containsExactly("com.example.DirectService");
  }

  @Test
  void detectsClassForNameConstantStringArgument() throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/ForNameApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "loadService", NO_ARG_VOID, null, null);
    method.visitCode();
    method.visitLdcInsn("com.example.ForNameService");
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/lang/Class",
        "forName",
        "(Ljava/lang/String;)Ljava/lang/Class;",
        false);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "load",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 0);
    method.visitEnd();
    writer.visitEnd();

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result =
        scanner.scan(new ByteArrayInputStream(writer.toByteArray()));

    assertThat(result.provenServiceInterfaces()).containsExactly("com.example.ForNameService");
  }

  @Test
  void detectsStaticFinalClassConstantField() throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/FieldApp", null, "java/lang/Object", null);
    writer.visitField(
        Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
        "SERVICE_CLASS",
        "Ljava/lang/Class;",
        null,
        null);

    final MethodVisitor clinit =
        writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", NO_ARG_VOID, null, null);
    clinit.visitCode();
    clinit.visitLdcInsn(Type.getObjectType("com/example/FieldService"));
    clinit.visitFieldInsn(
        Opcodes.PUTSTATIC, "sample/FieldApp", "SERVICE_CLASS", "Ljava/lang/Class;");
    clinit.visitInsn(Opcodes.RETURN);
    clinit.visitMaxs(1, 0);
    clinit.visitEnd();

    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "call", NO_ARG_VOID, null, null);
    method.visitCode();
    method.visitFieldInsn(
        Opcodes.GETSTATIC, "sample/FieldApp", "SERVICE_CLASS", "Ljava/lang/Class;");
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "load",
        "(Ljava/lang/Class;Ljava/lang/ClassLoader;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(2, 0);
    method.visitEnd();
    writer.visitEnd();

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result =
        scanner.scan(new ByteArrayInputStream(writer.toByteArray()));

    assertThat(result.provenServiceInterfaces()).containsExactly("com.example.FieldService");
  }

  @Test
  void detectsLocalVariableAssignment() throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/LocalVarApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", NO_ARG_VOID, null, null);
    method.visitCode();
    method.visitLdcInsn(Type.getObjectType("com/example/LocalVarService"));
    method.visitVarInsn(Opcodes.ASTORE, 1);
    method.visitVarInsn(Opcodes.ALOAD, 1);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "loadInstalled",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 2);
    method.visitEnd();
    writer.visitEnd();

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result =
        scanner.scan(new ByteArrayInputStream(writer.toByteArray()));

    assertThat(result.provenServiceInterfaces()).containsExactly("com.example.LocalVarService");
  }

  @Test
  void ignoresDynamicOrUnresolvableServiceLoaderCall() throws IOException {
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/DynamicApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "loadDynamic",
            "(Ljava/lang/Class;)V",
            null,
            null);
    method.visitCode();
    method.visitVarInsn(Opcodes.ALOAD, 0);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "load",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result =
        scanner.scan(new ByteArrayInputStream(writer.toByteArray()));

    assertThat(result.provenServiceInterfaces()).isEmpty();
  }

  @Test
  void scansDirectoryRecursively() throws IOException {
    final Path output = Files.createDirectory(tempDir.resolve("classes"));
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "sample/DirApp", null, "java/lang/Object", null);
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
    method.visitCode();
    method.visitLdcInsn(Type.getObjectType("com/example/DirectoryService"));
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        SERVICE_LOADER_INTERNAL,
        "load",
        "(Ljava/lang/Class;)Ljava/util/ServiceLoader;",
        false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(1, 1);
    method.visitEnd();
    writer.visitEnd();

    Files.write(output.resolve("DirApp.class"), writer.toByteArray());

    final ServiceLoaderCallScanner scanner = new ServiceLoaderCallScanner();
    final ServiceLoaderCallScanner.ScanResult result = scanner.scan(output);

    assertThat(result.provenServiceInterfaces()).containsExactly("com.example.DirectoryService");
  }
}
