/* WHY: Detects class-file attributes whose type references cannot be classified safely. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.TreeSet;

/** WHY: Unknown attributes can hide references from closed-world traversal. */
final class ClassFileAttributeInventory {
  /** WHY: Reject non-class bytes before reading any class-file offsets. */
  private static final int CLASS_FILE_MAGIC = 0xcafebabe;

  /** WHY: These attributes have known structures or no hidden type references. */
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

  /** WHY: UTF8 entries provide names used by the attribute inventory. */
  private static final int UTF8_CONSTANT_TAG = 1;

  /** WHY: Long and double entries occupy two constant-pool slots. */
  private static final int LONG_CONSTANT_TAG = 5;

  /** WHY: Double entries occupy two constant-pool slots. */
  private static final int DOUBLE_CONSTANT_TAG = 6;

  /** WHY: Code attributes contain nested method attributes. */
  private static final String CODE_ATTRIBUTE_NAME = "Code";

  /** WHY: Record attributes contain nested component attributes. */
  private static final String RECORD_ATTRIBUTE_NAME = "Record";

  /** WHY: Constant-pool payload widths indexed by tag, or -1 for invalid/UTF-8 tags. */
  private static final int[] CONSTANT_POOL_WIDTHS = {
    -1, -1, -1, 4, 4, 8, 8, 2, 2, 4, 4, 4, 4, -1, -1, 3, 2, 4, 4, 2, 2
  };

  private ClassFileAttributeInventory() {}

  // The default access modifier keeps this inventory internal to the trimmer.
  // WHY: Graph construction is the only consumer of the parsed attribute names.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static Set<String> unrecognizedAttributes(final byte[] bytes) throws IOException {
    final ByteCursor cursor = new ByteCursor(bytes, 0, bytes.length);
    if (cursor.readInt() != CLASS_FILE_MAGIC) {
      throw new IOException("Invalid class-file magic");
    }
    cursor.skip(4);
    final ConstantPoolUtf8Table utf8 = readConstantPool(cursor);
    cursor.skip(6);
    cursor.skip(cursor.readUnsignedShort() * 2L);
    Set<String> unrecognized = readMembers(cursor, utf8, null);
    unrecognized = readMembers(cursor, utf8, unrecognized);
    unrecognized = readAttributes(cursor, utf8, cursor.readUnsignedShort(), unrecognized);
    if (cursor.remaining() != 0) {
      throw new IOException("Unexpected trailing bytes after class attributes");
    }
    return unrecognized == null ? Set.of() : Set.copyOf(unrecognized);
  }

  private static ConstantPoolUtf8Table readConstantPool(final ByteCursor cursor)
      throws IOException {
    final int count = cursor.readUnsignedShort();
    final int[] offsets = new int[count];
    int index = 1;
    while (index < count) {
      final int tag = cursor.readUnsignedByte();
      if (tag == UTF8_CONSTANT_TAG) {
        final int lengthOffset = cursor.position();
        final int utfLength = cursor.readUnsignedShort();
        cursor.skip(utfLength);
        offsets[index] = lengthOffset;
      } else {
        cursor.skip(constantPoolEntryWidth(tag));
      }
      index += tag == LONG_CONSTANT_TAG || tag == DOUBLE_CONSTANT_TAG ? 2 : 1;
    }
    return new ConstantPoolUtf8Table(cursor.bytes, offsets);
  }

  private static int constantPoolEntryWidth(final int tag) throws IOException {
    if (tag < 0 || tag >= CONSTANT_POOL_WIDTHS.length || CONSTANT_POOL_WIDTHS[tag] < 0) {
      throw new IOException("Unknown class-file constant-pool tag: " + tag);
    }
    return CONSTANT_POOL_WIDTHS[tag];
  }

  private static Set<String> readMembers(
      final ByteCursor cursor,
      final ConstantPoolUtf8Table utf8,
      final Set<String> unrecognizedAttributes)
      throws IOException {
    Set<String> unrecognized = unrecognizedAttributes;
    final int count = cursor.readUnsignedShort();
    for (int index = 0; index < count; index++) {
      cursor.skip(6);
      unrecognized = readAttributes(cursor, utf8, cursor.readUnsignedShort(), unrecognized);
    }
    return unrecognized;
  }

  private static Set<String> readAttributes(
      final ByteCursor cursor,
      final ConstantPoolUtf8Table utf8,
      final int count,
      final Set<String> unrecognizedAttributes)
      throws IOException {
    Set<String> unrecognized = unrecognizedAttributes;
    for (int index = 0; index < count; index++) {
      final String name = utf8.at(cursor.readUnsignedShort());
      final long length = cursor.readUnsignedInt();
      if (length > Integer.MAX_VALUE) {
        throw new IOException("Class-file attribute is too large: " + name);
      }
      if (length > cursor.remaining()) {
        throw new IOException("Truncated class-file attribute: " + name);
      }
      if (!STANDARD_ATTRIBUTES.contains(name)) {
        unrecognized = addUnrecognized(unrecognized, name);
      }
      unrecognized = readAttributePayload(cursor, name, (int) length, utf8, unrecognized);
    }
    return unrecognized;
  }

  private static Set<String> addUnrecognized(final Set<String> unrecognized, final String name) {
    final Set<String> target = unrecognized == null ? new TreeSet<>() : unrecognized;
    target.add(name);
    return target;
  }

  private static Set<String> readAttributePayload(
      final ByteCursor cursor,
      final String name,
      final int length,
      final ConstantPoolUtf8Table utf8,
      final Set<String> unrecognized)
      throws IOException {
    if (CODE_ATTRIBUTE_NAME.equals(name)) {
      return readCodeAttribute(cursor, length, utf8, unrecognized);
    }
    if (RECORD_ATTRIBUTE_NAME.equals(name)) {
      return readRecordAttribute(cursor, length, utf8, unrecognized);
    }
    cursor.skip(length);
    return unrecognized;
  }

  private static Set<String> readCodeAttribute(
      final ByteCursor cursor,
      final int length,
      final ConstantPoolUtf8Table utf8,
      final Set<String> unrecognizedAttributes)
      throws IOException {
    final int end = cursor.position() + length;
    final ByteCursor nested = cursor.slice(length);
    nested.skip(4);
    final long codeLength = nested.readUnsignedInt();
    nested.skip(codeLength);
    nested.skip(nested.readUnsignedShort() * 8L);
    final Set<String> unrecognized =
        readAttributes(nested, utf8, nested.readUnsignedShort(), unrecognizedAttributes);
    if (nested.remaining() != 0) {
      throw new IOException("Malformed nested Code attribute");
    }
    cursor.advanceTo(end);
    return unrecognized;
  }

  private static Set<String> readRecordAttribute(
      final ByteCursor cursor,
      final int length,
      final ConstantPoolUtf8Table utf8,
      final Set<String> unrecognizedAttributes)
      throws IOException {
    final int end = cursor.position() + length;
    final ByteCursor nested = cursor.slice(length);
    Set<String> unrecognized = unrecognizedAttributes;
    final int components = nested.readUnsignedShort();
    for (int index = 0; index < components; index++) {
      nested.skip(4);
      unrecognized = readAttributes(nested, utf8, nested.readUnsignedShort(), unrecognized);
    }
    if (nested.remaining() != 0) {
      throw new IOException("Malformed nested Record attribute");
    }
    cursor.advanceTo(end);
    return unrecognized;
  }

  /** Lazy constant-pool UTF-8 table for attribute names. */
  private static final class ConstantPoolUtf8Table {
    /** Backing class-file bytes. */
    private final byte[] bytes;

    /** Offset of each CONSTANT_Utf8 length prefix, or 0 for non-UTF8 slots. */
    private final int[] offsets;

    /** Lazily decoded strings indexed by constant-pool slot. */
    private final String[] cache;

    private ConstantPoolUtf8Table(final byte[] bytes, final int... offsets) {
      this.bytes = bytes;
      this.offsets = offsets;
      this.cache = new String[offsets.length];
    }

    private String at(final int index) throws IOException {
      if (index <= 0 || index >= offsets.length || offsets[index] == 0) {
        throw new IOException("Invalid class-file attribute name index: " + index);
      }
      String cached = cache[index];
      if (cached == null) {
        cached = decode(offsets[index]);
        cache[index] = cached;
      }
      return cached;
    }

    private String decode(final int lengthOffset) throws IOException {
      final int utfLength = ((bytes[lengthOffset] & 0xff) << 8) | (bytes[lengthOffset + 1] & 0xff);
      final int dataOffset = lengthOffset + 2;
      for (int index = 0; index < utfLength; index++) {
        if (bytes[dataOffset + index] < 0) {
          return decodeModifiedUtf8(lengthOffset, utfLength);
        }
      }
      return new String(bytes, dataOffset, utfLength, StandardCharsets.US_ASCII);
    }

    private String decodeModifiedUtf8(final int lengthOffset, final int utfLength)
        throws IOException {
      try (DataInputStream input =
          new DataInputStream(new ByteArrayInputStream(bytes, lengthOffset, utfLength + 2))) {
        return input.readUTF();
      }
    }
  }

  /** Bounded big-endian cursor over a backing byte array. */
  private static final class ByteCursor {
    /** Backing byte array. */
    private final byte[] bytes;

    /** Exclusive upper bound in the backing byte array. */
    private final int limit;

    /** Current read position. */
    private int pos;

    private ByteCursor(final byte[] bytes, final int start, final int limit) {
      this.bytes = bytes;
      this.pos = start;
      this.limit = limit;
    }

    private int position() {
      return pos;
    }

    private int remaining() {
      return limit - pos;
    }

    private void advanceTo(final int nextPos) {
      pos = nextPos;
    }

    private ByteCursor slice(final int length) {
      return new ByteCursor(bytes, pos, pos + length);
    }

    private void requireRemaining(final long count) throws IOException {
      if (count < 0 || count > remaining()) {
        throw new EOFException("Unexpected end of class-file bytes");
      }
    }

    private void skip(final long count) throws IOException {
      requireRemaining(count);
      pos += (int) count;
    }

    private int readUnsignedByte() throws IOException {
      requireRemaining(1);
      final int value = bytes[pos] & 0xff;
      pos += 1;
      return value;
    }

    private int readUnsignedShort() throws IOException {
      requireRemaining(2);
      final int value = ((bytes[pos] & 0xff) << 8) | (bytes[pos + 1] & 0xff);
      pos += 2;
      return value;
    }

    private int readInt() throws IOException {
      requireRemaining(4);
      final int value =
          ((bytes[pos] & 0xff) << 24)
              | ((bytes[pos + 1] & 0xff) << 16)
              | ((bytes[pos + 2] & 0xff) << 8)
              | (bytes[pos + 3] & 0xff);
      pos += 4;
      return value;
    }

    private long readUnsignedInt() throws IOException {
      return Integer.toUnsignedLong(readInt());
    }
  }
}
