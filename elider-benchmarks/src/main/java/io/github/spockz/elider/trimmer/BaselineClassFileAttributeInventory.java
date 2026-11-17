/* WHY: Preserves the pre-optimization DataInputStream attribute inventory verbatim for JMH. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Verbatim pre-optimization DataInputStream attribute inventory. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class BaselineClassFileAttributeInventory {
  /** Reject non-class bytes before reading any class-file offsets. */
  private static final int CLASS_FILE_MAGIC = 0xcafebabe;

  /** These attributes have known structures or no hidden type references. */
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

  /** These widths let the class-file walk avoid reference callbacks. */
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

  /** UTF8 entries provide names used by the attribute inventory. */
  private static final int UTF8_CONSTANT_TAG = 1;

  /** Long and double entries occupy two constant-pool slots. */
  private static final int LONG_CONSTANT_TAG = 5;

  /** Double entries occupy two constant-pool slots. */
  private static final int DOUBLE_CONSTANT_TAG = 6;

  /** Code attributes contain nested method attributes. */
  private static final String CODE_ATTRIBUTE_NAME = "Code";

  /** Record attributes contain nested component attributes. */
  private static final String RECORD_ATTRIBUTE_NAME = "Record";

  private BaselineClassFileAttributeInventory() {}

  static Set<String> unrecognizedAttributes(final byte[] bytes) throws IOException {
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
      skipEntries(input, input.readUnsignedShort(), 2);
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
      final DataInputStream input, final String[] utf8, final Set<String> unrecognizedAttributes)
      throws IOException {
    final int count = input.readUnsignedShort();
    for (int index = 0; index < count; index++) {
      input.skipNBytes(6);
      readAttributes(input, utf8, input.readUnsignedShort(), unrecognizedAttributes);
    }
  }

  private static void readAttributes(
      final DataInputStream input,
      final String[] utf8,
      final int count,
      final Set<String> unrecognizedAttributes)
      throws IOException {
    for (int index = 0; index < count; index++) {
      final String name = utf8At(utf8, input.readUnsignedShort());
      final long length = Integer.toUnsignedLong(input.readInt());
      if (length > Integer.MAX_VALUE) {
        throw new IOException("Class-file attribute is too large: " + name);
      }
      final byte[] contents = input.readNBytes((int) length);
      if (contents.length != (int) length) {
        throw new IOException("Truncated class-file attribute: " + name);
      }
      if (!STANDARD_ATTRIBUTES.contains(name)) {
        unrecognizedAttributes.add(name);
      }
      if (CODE_ATTRIBUTE_NAME.equals(name)) {
        readCodeAttribute(contents, utf8, unrecognizedAttributes);
      } else if (RECORD_ATTRIBUTE_NAME.equals(name)) {
        readRecordAttribute(contents, utf8, unrecognizedAttributes);
      }
    }
  }

  private static void readCodeAttribute(
      final byte[] contents, final String[] utf8, final Set<String> unrecognizedAttributes)
      throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(contents))) {
      input.skipNBytes(4);
      final long codeLength = Integer.toUnsignedLong(input.readInt());
      input.skipNBytes(codeLength);
      skipEntries(input, input.readUnsignedShort(), 8);
      readAttributes(input, utf8, input.readUnsignedShort(), unrecognizedAttributes);
      requireConsumed(input, "Code");
    }
  }

  private static void readRecordAttribute(
      final byte[] contents, final String[] utf8, final Set<String> unrecognizedAttributes)
      throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(contents))) {
      final int components = input.readUnsignedShort();
      for (int index = 0; index < components; index++) {
        input.skipNBytes(4);
        readAttributes(input, utf8, input.readUnsignedShort(), unrecognizedAttributes);
      }
      requireConsumed(input, "Record");
    }
  }

  private static void skipEntries(
      final DataInputStream input, final int count, final int entryBytes) throws IOException {
    input.skipNBytes((long) count * entryBytes);
  }

  private static String utf8At(final String[] utf8, final int index) throws IOException {
    if (index <= 0 || index >= utf8.length || utf8[index] == null) {
      throw new IOException("Invalid class-file attribute name index: " + index);
    }
    return utf8[index];
  }

  private static void requireConsumed(final DataInputStream input, final String attribute)
      throws IOException {
    if (input.available() != 0) {
      throw new IOException("Malformed nested " + attribute + " attribute");
    }
  }
}
