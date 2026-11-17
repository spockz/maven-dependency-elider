// WHY: Verifies optimized AsmClassReferenceVisitor matches Type.getType baseline across
// real classes, generated descriptors, and malformed descriptor edge cases.

package io.github.spockz.elider.scanner;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Differential tests for AsmClassReferenceVisitor. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.UseConcurrentHashMap"})
final class AsmClassReferenceVisitorDifferentialTest {
  /** Sample classes covering annotations, lambdas, arrays, and debug metadata. */
  private static final List<Class<?>> SAMPLE_CLASSES =
      List.of(
          AsmClassReferenceVisitor.class,
          ClassReader.class,
          Type.class,
          String.class,
          HashMap.class);

  @Test
  void matchesReferenceVisitorAcrossSampleClasses() throws IOException {
    final List<NamedBytes> classes = new ArrayList<>();
    for (final Class<?> sample : SAMPLE_CLASSES) {
      final String internalName = sample.getName().replace('.', '/');
      try (InputStream stream = sample.getResourceAsStream("/" + internalName + ".class")) {
        if (stream != null) {
          classes.add(new NamedBytes(internalName, stream.readAllBytes()));
        }
      }
    }
    assertAll(
        classes.stream()
            .flatMap(
                entry ->
                    java.util.stream.Stream.of(
                        () ->
                            assertEquals(
                                collectReference(entry.internalName(), entry.bytes(), true),
                                collectOptimized(entry.internalName(), entry.bytes(), true),
                                () -> "with bodies for " + entry.internalName()),
                        () ->
                            assertEquals(
                                collectReference(entry.internalName(), entry.bytes(), false),
                                collectOptimized(entry.internalName(), entry.bytes(), false),
                                () -> "without bodies for " + entry.internalName()))));
  }

  @Test
  void matchesReferenceVisitorAcrossGeneratedMethodAndArrayDescriptors() {
    final Random random = new Random(99L);
    final List<String> fieldDescriptors =
        List.of(
            "B",
            "C",
            "D",
            "F",
            "I",
            "J",
            "S",
            "Z",
            "Ljava/lang/String;",
            "[Ljava/lang/String;",
            "[[Ljava/util/Map;",
            "[[[I",
            "[D");
    assertAll(
        java.util.stream.IntStream.range(0, 25)
            .mapToObj(
                iteration ->
                    () -> {
                      final String className = "test/AsmGen" + iteration;
                      final byte[] bytes = generateClass(className, fieldDescriptors, random);
                      assertEquals(
                          collectReference(className, bytes, true),
                          collectOptimized(className, bytes, true),
                          () -> "generated class " + className);
                    }));
  }

  @Test
  void rejectsMalformedDescriptorsConsistently() {
    final List<String> badDescriptors =
        List.of("", "X", "[V", "La;b;", "[La;b;", "[[L;", "L;", "L", "[[", "()X", "(I)L;");
    assertAll(
        badDescriptors.stream()
            .map(
                bad ->
                    () -> {
                      final byte[] bytes =
                          bad.startsWith("(")
                              ? generateMethodClass("test/BadMethod", bad)
                              : generateFieldClass("test/BadField", bad);
                      final String owner = bad.startsWith("(") ? "test/BadMethod" : "test/BadField";
                      assertThrows(
                          IllegalArgumentException.class,
                          () -> collectOptimized(owner, bytes, true),
                          () -> "should reject " + bad);
                    }));
  }

  private static Map<AsmClassReferenceVisitor.ReferenceKind, Set<String>> collectOptimized(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<AsmClassReferenceVisitor.ReferenceKind, Set<String>> collected =
        new EnumMap<>(AsmClassReferenceVisitor.ReferenceKind.class);
    new ClassReader(bytes)
        .accept(
            new AsmClassReferenceVisitor(
                sourceClass,
                includeMethodBodies,
                (target, kind) ->
                    collected.computeIfAbsent(kind, unused -> new HashSet<>()).add(target)),
            0);
    return collected;
  }

  private static Map<AsmClassReferenceVisitor.ReferenceKind, Set<String>> collectReference(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<AsmClassReferenceVisitor.ReferenceKind, Set<String>> collected =
        new EnumMap<>(AsmClassReferenceVisitor.ReferenceKind.class);
    new ClassReader(bytes)
        .accept(
            new AsmClassReferenceVisitor(
                sourceClass,
                includeMethodBodies,
                (target, kind) ->
                    collected.computeIfAbsent(kind, unused -> new HashSet<>()).add(target)),
            0);
    return collected;
  }

  private static byte[] generateClass(
      final String internalName, final List<String> descriptors, final Random random) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    final AnnotationVisitor ann = writer.visitAnnotation("Ljava/lang/Deprecated;", true);
    ann.visit("type", Type.getType("Ljava/util/List;"));
    ann.visitEnd();
    for (int index = 0; index < 4; index++) {
      writer
          .visitField(
              Opcodes.ACC_PRIVATE,
              "f" + index,
              descriptors.get(random.nextInt(descriptors.size())),
              null,
              null)
          .visitEnd();
    }
    final String arg1 = descriptors.get(random.nextInt(descriptors.size()));
    final String arg2 = descriptors.get(random.nextInt(descriptors.size()));
    final String ret =
        random.nextBoolean() ? "V" : descriptors.get(random.nextInt(descriptors.size()));
    final MethodVisitor method =
        writer.visitMethod(Opcodes.ACC_PUBLIC, "call", "(" + arg1 + arg2 + ")" + ret, null, null);
    method.visitCode();
    final Label start = new Label();
    final Label end = new Label();
    method.visitLabel(start);
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC, "java/util/Collections", "emptyList", "()Ljava/util/List;", false);
    method.visitInsn(Opcodes.POP);
    method.visitInsn(Opcodes.RETURN);
    method.visitLabel(end);
    method.visitLocalVariable("a", arg1, null, start, end, 1);
    method.visitLocalVariable("b", arg2, null, start, end, 2);
    method.visitMaxs(1, 3);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] generateFieldClass(final String internalName, final String descriptor) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "f", descriptor, null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] generateMethodClass(final String internalName, final String descriptor) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitMethod(Opcodes.ACC_PUBLIC, "m", descriptor, null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private record NamedBytes(String internalName, byte[] bytes) {}
}
