/* WHY: Shares bytecode/archive fixtures across focused signature-polymorphic tests. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;

/** Package-local class-file test fixtures. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SignaturePolymorphicTestSupport {
  /** Prevents utility instantiation. */
  private SignaturePolymorphicTestSupport() {}

  /** Shares API-backed analysis with package-local tests. */
  static DependencyJarTrimmer.TrimAnalysis analyze(final Path jar, final List<String> roots)
      throws IOException {
    final ClassPool api =
        new JdkApiClassPoolReader().read(Path.of(System.getProperty("java.home")), 21);
    return new DependencyJarTrimmer().analyze(jar, List.of(), api, roots);
  }

  /** Writes classes into an isolated test archive. */
  // A distinct ZipEntry is required for each serialized class entry.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  static Path writeClassJar(
      final Path directory, final String fileName, final Map<String, byte[]> classes)
      throws IOException {
    final Path jar = directory.resolve(fileName);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey()));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return jar;
  }

  /** Creates an invalid-reference caller for a negative test. */
  static Path writeMissingMemberCallJar(
      final Path directory,
      final String fileName,
      final String targetClass,
      final String memberName,
      final String memberDescriptor)
      throws IOException {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21, Opcodes.ACC_PUBLIC, "fixture/MissingMethod", null, "java/lang/Object", null);
    final org.objectweb.asm.MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
            "run",
            "(Ljava/lang/Object;)Ljava/lang/Object;",
            null,
            null);
    method.visitCode();
    method.visitVarInsn(Opcodes.ALOAD, 0);
    method.visitTypeInsn(Opcodes.CHECKCAST, targetClass);
    if (memberDescriptor.startsWith("(L")) {
      method.visitInsn(Opcodes.ACONST_NULL);
    }
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, targetClass, memberName, memberDescriptor, false);
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(2, 1);
    method.visitEnd();
    writer.visitEnd();
    return writeClassJar(
        directory, fileName, Map.of("fixture/MissingMethod.class", writer.toByteArray()));
  }

  /** Writes the retained class closure into an archive. */
  // A distinct ZipEntry is required for each serialized class entry.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  static Path writeRetainedJar(
      final Path directory, final Path candidateJar, final Set<String> names) throws IOException {
    final Path outputJar = directory.resolve("retained.jar");
    final Set<String> entries =
        names.stream().map(name -> name + ".class").collect(java.util.stream.Collectors.toSet());
    try (java.util.jar.JarFile input = new java.util.jar.JarFile(candidateJar.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(outputJar))) {
      for (final JarEntry entry : java.util.Collections.list(input.entries())) {
        if (entries.contains(entry.getName())) {
          output.putNextEntry(new JarEntry(entry.getName()));
          try (java.io.InputStream stream = input.getInputStream(entry)) {
            stream.transferTo(output);
          }
          output.closeEntry();
        }
      }
    }
    return outputJar;
  }
}
