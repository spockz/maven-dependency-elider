// WHY: Tests for AdvisoryJdkModulesAnalyzer ensuring sound jdeps module recommendations for jlink.

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.spi.ToolProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies advisory platform module analysis via jdeps. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.AtLeastOneConstructor",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.ShortVariable"
})
final class AdvisoryJdkModulesAnalyzerTest {
  private static final String JAVA_BASE = "java.base";

  @TempDir private Path tempDir;

  @Test
  @DisplayName("analyzes compiled class and extracts java.base module dependency")
  void analyzesClassesAndRecommendsModules() throws IOException {
    final Path classesDir = tempDir.resolve("classes");
    Files.createDirectories(classesDir);
    writeSimpleClass(classesDir.resolve("SimpleApp.class"));

    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final Set<String> modules = analyzer.analyze(List.of(classesDir), List.of(), 21);

    assertAll(
        () -> assertThat(modules).isNotEmpty(), () -> assertThat(modules).contains(JAVA_BASE));
  }

  @Test
  @DisplayName("formats modules as sorted newline-delimited output")
  void formatsSortedLines() {
    final Set<String> modules = Set.of("java.sql", JAVA_BASE, "java.logging");
    final String formatted = AdvisoryJdkModulesAnalyzer.formatModuleList(modules);

    assertThat(formatted).isEqualTo("java.base\njava.logging\njava.sql\n");
  }

  @Test
  @DisplayName("returns java.base without invoking jdeps when no existing inputs are present")
  void returnsBaseModuleWhenNoExistingInputs() throws IOException {
    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final Path missing = tempDir.resolve("missing.jar");

    final Set<String> empty = analyzer.analyze(List.of(), List.of(), 21);
    final Set<String> missingOnly = analyzer.analyze(List.of(missing), List.of(), 21);

    assertAll(
        "Empty or nonexistent inputs",
        () -> assertThat(empty).containsExactly(JAVA_BASE),
        () -> assertThat(missingOnly).containsExactly(JAVA_BASE));
  }

  @Test
  @DisplayName("fails with diagnostics when jdeps exits non-zero")
  void throwsOnNonZeroJdepsExitCode() throws IOException {
    final Path classesDir = tempDir.resolve("classes");
    Files.createDirectories(classesDir);
    writeSimpleClass(classesDir.resolve("SimpleApp.class"));

    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final ToolProvider failingJdeps =
        new ToolProvider() {
          @Override
          public String name() {
            return "jdeps";
          }

          @Override
          public int run(final PrintWriter out, final PrintWriter err, final String... args) {
            out.println("Usage: jdeps <options> <path ...>");
            err.println("Error: invalid option");
            return 2;
          }
        };

    assertThatThrownBy(() -> analyzer.analyze(List.of(classesDir), List.of(), 21, failingJdeps))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("jdeps failed with exit code 2")
        .hasMessageContaining("Error: invalid option");
  }

  @Test
  @DisplayName("analyzes Java 8 bytecode with retained MRJARs using --multi-release base")
  void analyzesJava8TargetWithRetainedMultiReleaseJar() throws IOException {
    final Path classesDir = tempDir.resolve("java8-classes");
    Files.createDirectories(classesDir);
    writeClassReferencing(
        classesDir.resolve("SqlClient.class"),
        Opcodes.V1_8,
        "SqlClient",
        "java/sql/Connection",
        "()V");
    final Path mrjar = writeMultiReleaseDependencyJar(tempDir.resolve("mrjar-dep.jar"));

    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final Set<String> java8Modules = analyzer.analyze(List.of(classesDir), List.of(mrjar), 8);
    final Set<String> java21MrjarModules = analyzer.analyze(List.of(mrjar), List.of(), 21);

    assertAll(
        "Target-aware MRJAR advisory analysis",
        () -> assertThat(java8Modules).contains(JAVA_BASE, "java.sql"),
        () -> assertThat(java21MrjarModules).contains(JAVA_BASE, "java.logging"));
  }

  @Test
  @DisplayName(
      "selects base tier for target 8 and versioned tier for target 21 when referencing MRJAR"
          + " helper")
  void selectsBaseTierForJava8AndVersionedTierForJava21WhenReferencingMrjarHelper()
      throws IOException {
    final Path classesDir = tempDir.resolve("helper-app-classes");
    Files.createDirectories(classesDir);
    writeClassReferencing(
        classesDir.resolve("AppClient.class"), Opcodes.V1_8, "AppClient", "dep/Helper", "()V");
    final Path mrjar = writeMultiReleaseDependencyJar(tempDir.resolve("mrjar-helper-dep.jar"));

    final AdvisoryJdkModulesAnalyzer analyzer = new AdvisoryJdkModulesAnalyzer();
    final Set<String> java8Modules = analyzer.analyze(List.of(classesDir), List.of(mrjar), 8);
    final Set<String> java21Modules = analyzer.analyze(List.of(classesDir), List.of(mrjar), 21);

    assertAll(
        "MRJAR tier selection by target release",
        () -> assertThat(java8Modules).containsExactly(JAVA_BASE).doesNotContain("java.logging"),
        () -> assertThat(java21Modules).contains(JAVA_BASE, "java.logging"));
  }

  private Path writeMultiReleaseDependencyJar(final Path jarPath) throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarPath), manifest)) {
      output.putNextEntry(new JarEntry("dep/Helper.class"));
      output.write(classBytes(Opcodes.V1_8, "dep/Helper", "java/lang/Object", "()V"));
      output.closeEntry();
      output.putNextEntry(new JarEntry("META-INF/versions/21/dep/Helper.class"));
      output.write(classBytes(Opcodes.V21, "dep/Helper", "java/util/logging/Logger", "()V"));
      output.closeEntry();
    }
    return jarPath;
  }

  private void writeClassReferencing(
      final Path classFile,
      final int version,
      final String internalName,
      final String referencedInternalName,
      final String descriptor)
      throws IOException {
    Files.write(classFile, classBytes(version, internalName, referencedInternalName, descriptor));
  }

  private byte[] classBytes(
      final int version,
      final String internalName,
      final String referencedInternalName,
      final String descriptor) {
    final ClassWriter cw = new ClassWriter(0);
    cw.visit(version, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    final MethodVisitor mv =
        cw.visitMethod(Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC, "use", descriptor, null, null);
    mv.visitCode();
    mv.visitLdcInsn(org.objectweb.asm.Type.getObjectType(referencedInternalName));
    mv.visitInsn(Opcodes.POP);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(1, 0);
    mv.visitEnd();
    cw.visitEnd();
    return cw.toByteArray();
  }

  private void writeSimpleClass(final Path classFile) throws IOException {
    final ClassWriter cw = new ClassWriter(0);
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "SimpleApp", null, "java/lang/Object", null);
    final MethodVisitor mv =
        cw.visitMethod(
            Opcodes.ACC_PUBLIC + Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null);
    mv.visitCode();
    mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
    mv.visitLdcInsn("hello");
    mv.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
    mv.visitInsn(Opcodes.RETURN);
    mv.visitMaxs(2, 1);
    mv.visitEnd();
    cw.visitEnd();
    Files.write(classFile, cw.toByteArray());
  }
}
