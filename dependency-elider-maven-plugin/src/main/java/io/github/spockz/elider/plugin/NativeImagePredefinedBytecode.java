/* WHY: Resolves predefined class hashes and extracts their bytecode type references. */

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;

/** Reads classdata associated with predefined-class configuration entries. */
final class NativeImagePredefinedBytecode {
  private NativeImagePredefinedBytecode() {}

  /* package */
  static Set<String> read(final JarFile archive, final String configName, final String hash)
      throws IOException {
    final JarEntry entry = archive.getJarEntry(bytecodePath(configName, hash));
    if (entry == null || entry.isDirectory()) {
      throw new IOException("Unresolved predefined class hash " + hash + " in " + configName);
    }
    final byte[] bytes;
    try (InputStream input = archive.getInputStream(entry)) {
      bytes = input.readAllBytes();
    }
    return parseClass(bytes, configName, hash);
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

  private static String bytecodePath(final String configName, final String hash) {
    final int slash = configName.lastIndexOf('/');
    return configName.substring(0, slash + 1)
        + "agent-extracted-predefined-classes/"
        + hash
        + ".classdata";
  }
}
