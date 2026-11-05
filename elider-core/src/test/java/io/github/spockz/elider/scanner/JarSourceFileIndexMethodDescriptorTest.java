/* WHY: Ensures the JAR scanner preserves JVM descriptors needed to disambiguate overloads. */

package io.github.spockz.elider.scanner;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Exercises descriptor extraction from class files in a local archive. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AvoidDuplicateLiterals"})
final class JarSourceFileIndexMethodDescriptorTest {
  /** Temporary output folder for generated archives. */
  @TempDir private Path tempDir;

  @Test
  void retainsNamesAndDescriptorsForOverloadedMethods() throws IOException {
    final Path archive = tempDir.resolve("overloads.jar");
    final ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
    writer.visit(
        Opcodes.V17, Opcodes.ACC_PUBLIC, "org/example/Owner", null, "java/lang/Object", null);
    addMethod(writer, "run", "()V");
    addMethod(writer, "run", "(I)V");
    writer.visitEnd();
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(archive))) {
      output.putNextEntry(new JarEntry("org/example/Owner.class"));
      output.write(writer.toByteArray());
      output.closeEntry();
    }

    assertThat(JarSourceFileIndex.read(archive).classFiles())
        .singleElement()
        .extracting(JarSourceFileIndex.ClassSourceFile::declaredMethods)
        .isEqualTo(
            Set.of(
                new JarSourceFileIndex.MethodIdentity("run", "()V"),
                new JarSourceFileIndex.MethodIdentity("run", "(I)V")));
  }

  private static void addMethod(
      final ClassWriter writer, final String name, final String descriptor) {
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, name, descriptor, null, null);
    method.visitCode();
    method.visitInsn(Opcodes.RETURN);
    method.visitMaxs(0, 0);
    method.visitEnd();
  }
}
