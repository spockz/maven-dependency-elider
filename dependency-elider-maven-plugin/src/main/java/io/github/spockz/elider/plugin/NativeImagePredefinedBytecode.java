/* WHY: Resolves predefined class hashes and extracts their bytecode type references. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import org.objectweb.asm.ClassReader;

/** Reads classdata associated with predefined-class configuration entries. */
final class NativeImagePredefinedBytecode {
  private NativeImagePredefinedBytecode() {}

  /* package */
  static Set<String> read(final NativeImageInput input, final String hash) throws IOException {
    final byte[] bytes;
    try {
      try (InputStream data = input.openSibling(bytecodePath(hash))) {
        bytes = data.readAllBytes();
      }
    } catch (IOException exception) {
      throw new IOException(
          "Unresolved predefined class hash " + hash + " in " + input.name(), exception);
    }
    return parseClass(bytes, input.name(), hash);
  }

  private static Set<String> parseClass(
      final byte[] bytes, final String configName, final String hash) throws IOException {
    if (bytes.length < 10
        || bytes[0] != (byte) 0xca
        || bytes[1] != (byte) 0xfe
        || bytes[2] != (byte) 0xba
        || bytes[3] != (byte) 0xbe) {
      throw malformedClass(hash, configName, null);
    }
    final Set<String> references = new HashSet<>();
    try {
      new ClassReader(bytes).accept(new NativeImagePredefinedClassVisitor(references), 0);
    } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException exception) {
      throw malformedClass(hash, configName, exception);
    }
    return Set.copyOf(references);
  }

  private static IOException malformedClass(
      final String hash, final String configName, final RuntimeException cause) {
    return new IOException(
        "Malformed predefined class bytecode for " + hash + " in " + configName, cause);
  }

  private static String bytecodePath(final String hash) {
    return "agent-extracted-predefined-classes/" + hash + ".classdata";
  }
}
