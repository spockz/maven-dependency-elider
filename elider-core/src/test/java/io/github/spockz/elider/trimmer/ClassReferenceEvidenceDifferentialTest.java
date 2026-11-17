// WHY: Verifies optimized ClassReferenceEvidence edge classification matches the reference EnumSet
// implementation across real compiled classes and descriptor edge cases.

package io.github.spockz.elider.trimmer;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.spockz.elider.scanner.AsmClassReferenceVisitor;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies optimized ClassReferenceEvidence edge classification. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ClassReferenceEvidenceDifferentialTest {
  /** Representative classes used for differential bytecode reference checks. */
  private static final List<Class<?>> SAMPLE_CLASSES =
      List.of(
          ClassReferenceEvidence.class,
          ClassFileAttributeInventory.class,
          ReferenceGraphBuilder.class,
          ReferenceGraphIndexer.class,
          AsmClassReferenceVisitor.class,
          FrozenClassPool.class,
          LazyPlatformClassPool.class,
          JdkPlatformContext.class);

  @Test
  void matchesReferenceEnumSetCollectorAcrossSampleClasses() throws IOException {
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
                                referenceReferences(entry.internalName(), entry.bytes(), true),
                                ClassReferenceEvidence.references(
                                        entry.internalName(), entry.bytes(), true)
                                    .references(),
                                () -> "with bodies for " + entry.internalName()),
                        () ->
                            assertEquals(
                                referenceReferences(entry.internalName(), entry.bytes(), false),
                                ClassReferenceEvidence.references(
                                        entry.internalName(), entry.bytes(), false)
                                    .references(),
                                () -> "without bodies for " + entry.internalName()))));
  }

  @Test
  void matchesReferenceCollectorAcrossGeneratedArrayAndGenericDescriptors() {
    final Random random = new Random(42L);
    final List<String> descriptors =
        List.of(
            "Ljava/lang/String;",
            "[Ljava/lang/String;",
            "[[Ljava/util/Map;",
            "[[[I",
            "J",
            "Z",
            "[D");
    assertAll(
        java.util.stream.IntStream.range(0, 20)
            .mapToObj(
                iteration ->
                    () -> {
                      final String className = "test/GeneratedSample" + iteration;
                      final byte[] bytes = generateClass(className, descriptors, random);
                      final boolean includeBodies = (iteration & 1) == 0;
                      assertEquals(
                          referenceReferences(className, bytes, includeBodies),
                          ClassReferenceEvidence.references(className, bytes, includeBodies)
                              .references(),
                          () -> "generated class " + className);
                    }));
  }

  @Test
  void rejectsMalformedArrayAndObjectDescriptorsConsistently() {
    final List<String> invalidDescriptors = List.of("La;b;", "[La;b;", "[[L;", "L;", "L", "[[");
    assertAll(
        invalidDescriptors.stream()
            .map(
                badDescriptor ->
                    () -> {
                      final byte[] bytes = generateFieldClass("test/BadDesc", badDescriptor);
                      assertThrows(
                          IllegalArgumentException.class,
                          () -> ClassReferenceEvidence.references("test/BadDesc", bytes, true),
                          () -> "should reject descriptor " + badDescriptor);
                    }));
  }

  private static byte[] generateClass(
      final String internalName, final List<String> descriptors, final Random random) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    for (int index = 0; index < 4; index++) {
      final String descriptor = descriptors.get(random.nextInt(descriptors.size()));
      writer.visitField(Opcodes.ACC_PRIVATE, "field" + index, descriptor, null, null).visitEnd();
    }
    final String argDesc = descriptors.get(random.nextInt(descriptors.size()));
    final String retDesc = descriptors.get(random.nextInt(descriptors.size()));
    final MethodVisitor method =
        writer.visitMethod(
            Opcodes.ACC_PUBLIC, "compute", "(" + argDesc + ")" + retDesc, null, null);
    method.visitCode();
    method.visitInsn(Opcodes.ACONST_NULL);
    method.visitInsn(Opcodes.ARETURN);
    method.visitMaxs(1, 2);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static byte[] generateFieldClass(
      final String internalName, final String fieldDescriptor) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitField(Opcodes.ACC_PRIVATE, "broken", fieldDescriptor, null, null).visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Set<ReferenceGraph.EdgeKind>> referenceReferences(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<String, Set<ReferenceGraph.EdgeKind>> references = new LinkedHashMap<>();
    references
        .computeIfAbsent(sourceClass, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
        .add(ReferenceGraph.EdgeKind.STRUCTURAL);
    new ClassReader(bytes)
        .accept(
            new AsmClassReferenceVisitor(
                sourceClass,
                includeMethodBodies,
                (target, kind) ->
                    references
                        .computeIfAbsent(
                            target, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
                        .add(
                            switch (kind) {
                              case STRUCTURAL -> ReferenceGraph.EdgeKind.STRUCTURAL;
                              case BODY -> ReferenceGraph.EdgeKind.BODY;
                              case DEBUG_METADATA -> ReferenceGraph.EdgeKind.DEBUG_METADATA;
                            })),
            0);
    final Map<String, Set<ReferenceGraph.EdgeKind>> immutable = new HashMap<>();
    references.forEach((target, kinds) -> immutable.put(target, Set.copyOf(kinds)));
    return Map.copyOf(immutable);
  }

  private record NamedBytes(String internalName, byte[] bytes) {}
}
