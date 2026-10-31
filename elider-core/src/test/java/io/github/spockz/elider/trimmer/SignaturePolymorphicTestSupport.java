/* WHY: Shares bytecode/archive fixtures across focused signature-polymorphic tests. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;

/** Package-local class-file test fixtures. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class SignaturePolymorphicTestSupport {
  /** WHY: Reuses immutable declarations; models are rematerialized per call. */
  private static final ConcurrentMap<Path, List<LibraryClassTemplate>> JAVA_21_TEMPLATE_READS =
      new ConcurrentHashMap<>();

  /** WHY: One read populates each immutable JDK template snapshot. */
  private static final Lock JAVA_21_TEMPLATE_LOCK = new ReentrantLock();

  /** Prevents utility instantiation. */
  private SignaturePolymorphicTestSupport() {}

  /** Shares API-backed analysis with package-local tests. */
  static DependencyJarTrimmer.TrimAnalysis analyze(final Path jar, final List<String> roots)
      throws IOException {
    return new DependencyJarTrimmer().analyze(jar, List.of(), java21ApiPool(), roots);
  }

  static ClassPool java21ApiPool() throws IOException {
    final Path javaHome = Path.of(System.getProperty("java.home"));
    final List<LibraryClassTemplate> templates = templatesFor(javaHome);
    final ClassPool freshPool = new ClassPool();
    for (final LibraryClassTemplate template : templates) {
      freshPool.addClass(template.materialize());
    }
    return freshPool;
  }

  private static List<LibraryClassTemplate> templatesFor(final Path javaHome) throws IOException {
    JAVA_21_TEMPLATE_LOCK.lock();
    try {
      List<LibraryClassTemplate> templates = JAVA_21_TEMPLATE_READS.get(javaHome);
      if (templates == null) {
        templates = readTemplates(javaHome);
        JAVA_21_TEMPLATE_READS.put(javaHome, templates);
      }
      return templates;
    } finally {
      JAVA_21_TEMPLATE_LOCK.unlock();
    }
  }

  private static List<LibraryClassTemplate> readTemplates(final Path javaHome) throws IOException {
    final ClassPool parsedApi = new JdkApiClassPoolReader().read(javaHome, 21);
    final List<LibraryClassTemplate> capturedTemplates = new ArrayList<>();
    for (final Clazz clazz : parsedApi.classes()) {
      if (!(clazz instanceof LibraryClass libraryClass)) {
        throw new IOException("JDK API test pool contains a non-library class");
      }
      capturedTemplates.add(LibraryClassTemplate.from(libraryClass));
    }
    return List.copyOf(capturedTemplates);
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
