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
    final Set<String> references = new HashSet<>();
    try {
      new ClassReader(bytes).accept(new NativeImagePredefinedClassVisitor(references), 0);
    } catch (IllegalArgumentException exception) {
      throw new IOException(
          "Malformed predefined class bytecode for " + hash + " in " + configName, exception);
    }
    return Set.copyOf(references);
  }

  private static String bytecodePath(final String hash) {
    return "agent-extracted-predefined-classes/" + hash + ".classdata";
  }
}
