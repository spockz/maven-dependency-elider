/* WHY: Confirms the descriptor-only fixture has no class constant naming its linked type. */

package io.github.spockz.elider.trimmer;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.Set;

/** Reads only the class constant references needed by one semantic regression. */
public final class ClassFileConstantPool {
  /** Constant-pool tags storing a single two-byte index. */
  private static final Set<Integer> TWO_BYTE_TAGS = Set.of(8, 16, 19, 20);

  /** Constant-pool tags storing two two-byte indexes. */
  private static final Set<Integer> FOUR_BYTE_TAGS = Set.of(9, 10, 11, 12, 17, 18);

  /** JVM constant-pool tag for a class-name reference. */
  private static final int CLASS_CONSTANT_TAG = 7;

  /** JVM constant-pool tag for a method-handle reference. */
  private static final int METHOD_HANDLE_CONSTANT_TAG = 15;

  /** JVM constant-pool tag for modified UTF-8 text. */
  private static final int UTF8_CONSTANT_TAG = 1;

  private ClassFileConstantPool() {}

  /** Checks whether the class-file constant pool names the requested class. */
  public static boolean containsClassConstant(final byte[] classFile, final String expectedName)
      throws IOException {
    try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(classFile))) {
      input.readInt();
      input.readUnsignedShort();
      input.readUnsignedShort();
      final int count = input.readUnsignedShort();
      final String[] utf8 = new String[count];
      final int[] classIndices = new int[count];
      int index = 1;
      while (index < count) {
        index += readEntry(input, input.readUnsignedByte(), index, utf8, classIndices);
      }
      return classIndexNamesExpected(classIndices, utf8, expectedName);
    }
  }

  private static boolean classIndexNamesExpected(
      final int[] classIndices, final String[] utf8, final String expectedName) {
    for (final int nameIndex : classIndices) {
      if (nameIndex != 0 && expectedName.equals(utf8[nameIndex])) {
        return true;
      }
    }
    return false;
  }

  private static int readEntry(
      final DataInputStream input,
      final int tag,
      final int index,
      final String[] utf8,
      final int... classIndices)
      throws IOException {
    if (tag == UTF8_CONSTANT_TAG) {
      utf8[index] = input.readUTF();
      return 1;
    }
    return readOtherEntry(input, tag, index, classIndices);
  }

  private static int readOtherEntry(
      final DataInputStream input, final int tag, final int index, final int... classIndices)
      throws IOException {
    if (tag == 3 || tag == 4) {
      input.skipNBytes(4);
      return 1;
    }
    if (tag == 5 || tag == 6) {
      input.skipNBytes(8);
      return 2;
    }
    return readReferenceEntry(input, tag, index, classIndices);
  }

  private static int readReferenceEntry(
      final DataInputStream input, final int tag, final int index, final int... classIndices)
      throws IOException {
    if (tag == CLASS_CONSTANT_TAG) {
      classIndices[index] = input.readUnsignedShort();
      return 1;
    }
    if (TWO_BYTE_TAGS.contains(tag)) {
      input.readUnsignedShort();
      return 1;
    }
    if (FOUR_BYTE_TAGS.contains(tag)) {
      input.skipNBytes(4);
      return 1;
    }
    if (tag == METHOD_HANDLE_CONSTANT_TAG) {
      input.skipNBytes(3);
      return 1;
    }
    throw new IOException("Unknown class-file constant-pool tag");
  }
}
