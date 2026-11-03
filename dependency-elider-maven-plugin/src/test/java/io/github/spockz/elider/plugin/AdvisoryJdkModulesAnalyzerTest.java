// WHY: Tests for AdvisoryJdkModulesAnalyzer ensuring sound jdeps module recommendations for jlink.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

final class AdvisoryJdkModulesAnalyzerTest {

  @TempDir
  private Path tempDir;

  @Test
  @DisplayName("analyzes compiled class and extracts java.base module dependency")
  void analyzesClassesAndRecommendsModules() throws IOException {
    final Path classesDir = tempDir.resolve("classes");
    Files.createDirectories(classesDir);
    writeSimpleClass(classesDir.resolve("SimpleApp.class"));

    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final Set<String> modules = analyzer.analyze(List.of(classesDir), List.of(), 21);

    assertAll(
        () -> assertThat(modules).isNotEmpty(),
        () -> assertThat(modules).contains("java.base"));
  }

  @Test
  @DisplayName("formats modules as sorted newline-delimited output")
  void formatsSortedLines() {
    final Set<String> modules = Set.of("java.sql", "java.base", "java.logging");
    final String formatted = AdvisoryJdkModulesAnalyzer.formatModuleList(modules);

    assertThat(formatted).isEqualTo("java.base\njava.logging\njava.sql\n");
  }

  private void writeSimpleClass(final Path classFile) throws IOException {
    final ClassWriter cw = new ClassWriter(0);
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "SimpleApp", null, "java/lang/Object", null);
    final MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
    mv.visitCode();
    mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
    mv.visitLdcInsn("hello");
    mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(2, 1);
    mv.visitEnd();
    cw.visitEnd();
    Files.write(classFile, cw.toByteArray());
  }
}
