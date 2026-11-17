// WHY: Verifies byte-cursor ClassFileAttributeInventory matches the DataInputStream reference
// implementation across real classes, generated nested attributes, and malformed inputs.

package io.github.spockz.elider.trimmer;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.spockz.elider.scanner.AsmClassReferenceVisitor;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.RecordComponentVisitor;

/** Verifies ClassFileAttributeInventory against DataInputStream baseline. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ClassFileAttributeInventoryDifferentialTest {
  /** Standard class-file magic header. */
  private static final int CLASS_FILE_MAGIC = 0xcafebabe;

  /** Constant-pool tag for UTF-8 strings. */
  private static final int UTF8_CONSTANT_TAG = 1;

  /** Constant-pool tag for 64-bit longs (occupies two slots). */
  private static final int LONG_CONSTANT_TAG = 5;

  /** Constant-pool tag for 64-bit doubles (occupies two slots). */
  private static final int DOUBLE_CONSTANT_TAG = 6;

  /** Standard Code attribute name. */
  private static final String CODE_ATTRIBUTE_NAME = "Code";

  /** Standard Record attribute name. */
  private static final String RECORD_ATTRIBUTE_NAME = "Record";

  /** Sample classes covering standard, debug, and inner-class attributes. */
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

  /** Standard attributes recognized by the reference inventory. */
  private static final Set<String> STANDARD_ATTRIBUTES =
      Set.of(
          "AnnotationDefault",
          "BootstrapMethods",
          "Code",
          "ConstantValue",
          "Deprecated",
          "EnclosingMethod",
          "Exceptions",
          "InnerClasses",
          "LineNumberTable",
          "LocalVariableTable",
          "LocalVariableTypeTable",
          "MethodParameters",
          "Module",
          "ModuleHashes",
          "ModuleMainClass",
          "ModulePackages",
          "ModuleResolution",
          "ModuleTarget",
          "NestHost",
          "NestMembers",
          "PermittedSubclasses",
          "Record",
          "RuntimeInvisibleAnnotations",
          "RuntimeInvisibleParameterAnnotations",
          "RuntimeInvisibleTypeAnnotations",
          "RuntimeVisibleAnnotations",
          "RuntimeVisibleParameterAnnotations",
          "RuntimeVisibleTypeAnnotations",
          "Signature",
          "SourceDebugExtension",
          "SourceFile",
          "StackMapTable",
          "Synthetic");

  /** Constant-pool payload widths for non-UTF8 tags. */
  private static final Map<Integer, Integer> CONSTANT_POOL_ENTRY_BYTES =
      Map.ofEntries(
          Map.entry(3, 4),
          Map.entry(4, 4),
          Map.entry(5, 8),
          Map.entry(6, 8),
          Map.entry(7, 2),
          Map.entry(8, 2),
          Map.entry(9, 4),
          Map.entry(10, 4),
          Map.entry(11, 4),
          Map.entry(12, 4),
          Map.entry(15, 3),
          Map.entry(16, 2),
          Map.entry(17, 4),
          Map.entry(18, 4),
          Map.entry(19, 2),
          Map.entry(20, 2));

  @Test
  void matchesReferenceAcrossSampleClasses() throws IOException {
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
            .map(
                entry ->
                    () ->
                        assertEquals(
                            referenceUnrecognizedAttributes(entry.bytes()),
                            ClassFileAttributeInventory.unrecognizedAttributes(entry.bytes()),
                            () -> "attributes for " + entry.internalName())));
  }

  @Test
  void matchesReferenceAcrossGeneratedClassesWithCustomAndRecordAttributes() {
    final Random random = new Random(17L);
    assertAll(
        java.util.stream.IntStream.range(0, 25)
            .mapToObj(
                iteration ->
                    () -> {
                      final byte[] bytes = generateClassWithAttributes(iteration, random);
                      assertEquals(
                          referenceUnrecognizedAttributes(bytes),
                          ClassFileAttributeInventory.unrecognizedAttributes(bytes),
                          () -> "generated class iteration " + iteration);
                    }));
  }

  @Test
  void rejectsMalformedAndTruncatedInputsConsistently() throws IOException {
    final byte[] valid = generateClassWithAttributes(1, new Random(7L));
    final byte[] badMagic = valid.clone();
    badMagic[0] = 0;
    final byte[] trailing = new byte[valid.length + 1];
    System.arraycopy(valid, 0, trailing, 0, valid.length);
    final byte[] truncated = java.util.Arrays.copyOf(valid, valid.length - 2);
    final byte[] empty = new byte[0];

    assertAll(
        () -> {
          assertThrows(IOException.class, () -> referenceUnrecognizedAttributes(badMagic));
          assertThrows(
              IOException.class,
              () -> ClassFileAttributeInventory.unrecognizedAttributes(badMagic));
        },
        () -> {
          assertThrows(IOException.class, () -> referenceUnrecognizedAttributes(trailing));
          assertThrows(
              IOException.class,
              () -> ClassFileAttributeInventory.unrecognizedAttributes(trailing));
        },
        () -> {
          assertThrows(IOException.class, () -> referenceUnrecognizedAttributes(truncated));
          assertThrows(
              IOException.class,
              () -> ClassFileAttributeInventory.unrecognizedAttributes(truncated));
        },
        () -> {
          assertThrows(IOException.class, () -> referenceUnrecognizedAttributes(empty));
          assertThrows(
              IOException.class, () -> ClassFileAttributeInventory.unrecognizedAttributes(empty));
        });
  }

  private static byte[] generateClassWithAttributes(final int iteration, final Random random) {
    final boolean isRecord = (iteration & 1) == 0;
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(
        Opcodes.V21,
        Opcodes.ACC_PUBLIC | (isRecord ? Opcodes.ACC_RECORD : 0),
        "test/AttrSample" + iteration,
        null,
        isRecord ? "java/lang/Record" : "java/lang/Object",
        null);
    if (isRecord) {
      final RecordComponentVisitor component = writer.visitRecordComponent("value", "I", null);
      if (random.nextBoolean()) {
        component.visitAttribute(new CustomAttribute("CustomRecordComp" + iteration, 3));
      }
      component.visitEnd();
    }
    if (random.nextBoolean()) {
      writer.visitAttribute(new CustomAttribute("CustomClassAttr" + iteration, 5));
    }
    final MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
    method.visitCode();
    method.visitInsn(Opcodes.RETURN);
    if (random.nextBoolean()) {
      method.visitAttribute(new CustomAttribute("CustomMethodAttr" + iteration, 2));
    }
    method.visitMaxs(0, 1);
    method.visitEnd();
    writer.visitEnd();
    return writer.toByteArray();
  }

  private static Set<String> referenceUnrecognizedAttributes(final byte[] bytes)
      throws IOException {
    return ReferenceInventory.unrecognizedAttributes(bytes);
  }

  /** Reference DataInputStream-based attribute inventory for differential comparison. */
  private static final class ReferenceInventory {
    private static Set<String> unrecognizedAttributes(final byte[] bytes) throws IOException {
      final Set<String> unrecognized = new TreeSet<>();
      try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(bytes))) {
        if (input.readInt() != CLASS_FILE_MAGIC) {
          throw new IOException("Invalid class-file magic");
        }
        input.readUnsignedShort();
        input.readUnsignedShort();
        final String[] utf8 = readConstantPool(input);
        input.readUnsignedShort();
        input.readUnsignedShort();
        input.readUnsignedShort();
        input.skipNBytes((long) input.readUnsignedShort() * 2);
        readMembers(input, utf8, unrecognized);
        readMembers(input, utf8, unrecognized);
        readAttributes(input, utf8, input.readUnsignedShort(), unrecognized);
        if (input.available() != 0) {
          throw new IOException("Unexpected trailing bytes after class attributes");
        }
      }
      return Set.copyOf(unrecognized);
    }

    private static String[] readConstantPool(final DataInputStream input) throws IOException {
      final int count = input.readUnsignedShort();
      final String[] utf8 = new String[count];
      int index = 1;
      while (index < count) {
        final int tag = input.readUnsignedByte();
        if (tag == UTF8_CONSTANT_TAG) {
          utf8[index] = input.readUTF();
        } else {
          final Integer width = CONSTANT_POOL_ENTRY_BYTES.get(tag);
          if (width == null) {
            throw new IOException("Unknown class-file constant-pool tag: " + tag);
          }
          input.skipNBytes(width);
        }
        index += tag == LONG_CONSTANT_TAG || tag == DOUBLE_CONSTANT_TAG ? 2 : 1;
      }
      return utf8;
    }

    private static void readMembers(
        final DataInputStream input, final String[] utf8, final Set<String> unrecognized)
        throws IOException {
      final int count = input.readUnsignedShort();
      for (int index = 0; index < count; index++) {
        input.skipNBytes(6);
        readAttributes(input, utf8, input.readUnsignedShort(), unrecognized);
      }
    }

    private static void readAttributes(
        final DataInputStream input,
        final String[] utf8,
        final int count,
        final Set<String> unrecognized)
        throws IOException {
      for (int index = 0; index < count; index++) {
        final String name = resolveAttributeName(utf8, input.readUnsignedShort());
        final byte[] contents = readAttributeBytes(input, name);
        if (!STANDARD_ATTRIBUTES.contains(name)) {
          unrecognized.add(name);
        }
        readNestedAttribute(name, contents, utf8, unrecognized);
      }
    }

    private static String resolveAttributeName(final String[] utf8, final int nameIndex)
        throws IOException {
      if (nameIndex <= 0 || nameIndex >= utf8.length || utf8[nameIndex] == null) {
        throw new IOException("Invalid class-file attribute name index: " + nameIndex);
      }
      return utf8[nameIndex];
    }

    private static byte[] readAttributeBytes(final DataInputStream input, final String name)
        throws IOException {
      final long length = Integer.toUnsignedLong(input.readInt());
      if (length > Integer.MAX_VALUE) {
        throw new IOException("Class-file attribute is too large: " + name);
      }
      final byte[] contents = input.readNBytes((int) length);
      if (contents.length != (int) length) {
        throw new IOException("Truncated class-file attribute: " + name);
      }
      return contents;
    }

    private static void readNestedAttribute(
        final String name,
        final byte[] contents,
        final String[] utf8,
        final Set<String> unrecognized)
        throws IOException {
      if (CODE_ATTRIBUTE_NAME.equals(name)) {
        readCodeAttribute(contents, utf8, unrecognized);
      } else if (RECORD_ATTRIBUTE_NAME.equals(name)) {
        readRecordAttribute(contents, utf8, unrecognized);
      }
    }

    private static void readCodeAttribute(
        final byte[] contents, final String[] utf8, final Set<String> unrecognized)
        throws IOException {
      try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(contents))) {
        input.skipNBytes(4);
        final long codeLength = Integer.toUnsignedLong(input.readInt());
        input.skipNBytes(codeLength);
        input.skipNBytes((long) input.readUnsignedShort() * 8);
        readAttributes(input, utf8, input.readUnsignedShort(), unrecognized);
        if (input.available() != 0) {
          throw new IOException("Malformed nested Code attribute");
        }
      }
    }

    private static void readRecordAttribute(
        final byte[] contents, final String[] utf8, final Set<String> unrecognized)
        throws IOException {
      try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(contents))) {
        final int components = input.readUnsignedShort();
        for (int index = 0; index < components; index++) {
          input.skipNBytes(4);
          readAttributes(input, utf8, input.readUnsignedShort(), unrecognized);
        }
        if (input.available() != 0) {
          throw new IOException("Malformed nested Record attribute");
        }
      }
    }
  }

  private record NamedBytes(String internalName, byte[] bytes) {}

  /** Synthetic custom attribute for differential testing. */
  private static final class CustomAttribute extends Attribute {
    /** Number of zero bytes to emit as attribute payload. */
    private final int payloadBytes;

    private CustomAttribute(final String type, final int payloadBytes) {
      super(type);
      this.payloadBytes = payloadBytes;
    }

    @Override
    protected ByteVector write(
        final ClassWriter classWriter,
        final byte[] code,
        final int codeLength,
        final int maxStack,
        final int maxLocals) {
      final ByteVector vector = new ByteVector(payloadBytes);
      for (int index = 0; index < payloadBytes; index++) {
        vector.putByte(index);
      }
      return vector;
    }
  }
}
