/* WHY: Shares byte-preserving ZIP copying and class-name validation across MR writer handlers. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.objectweb.asm.ClassReader;

/** Low-level helpers for writing an MRJAR entry and validating its class identity. */
@SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
final class MultiReleaseEntrySupport {
  private static final String CLASS_SUFFIX = ".class";

  private MultiReleaseEntrySupport() {}

  static String readClassName(final JarFile input, final JarEntry entry) throws IOException {
    final String className;
    try (InputStream classInput = input.getInputStream(entry)) {
      className = new ClassReader(classInput).getClassName();
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException("Could not read class entry: " + entry.getName(), exception);
    }
    if (!entry.getName().equals(className + CLASS_SUFFIX)) {
      throw new IOException(
          "Class entry path does not match its declared name: " + entry.getName());
    }
    return className;
  }

  static boolean isModuleDescriptor(final String name) {
    return "module-info.class".equals(name) || name.endsWith("/module-info.class");
  }

  static String logicalClassName(final String entryName) {
    final String versionsPrefix = "META-INF/versions/";
    if (!entryName.startsWith(versionsPrefix)) {
      return entryName.substring(0, entryName.length() - CLASS_SUFFIX.length());
    }
    final int versionEnd = entryName.indexOf('/', versionsPrefix.length());
    return entryName.substring(versionEnd + 1, entryName.length() - CLASS_SUFFIX.length());
  }

  static void writeEntryAs(
      final JarFile input,
      final JarOutputStream output,
      final JarEntry original,
      final String outputName)
      throws IOException {
    final JarEntry copy = copyMetadata(original, outputName);
    output.putNextEntry(copy);
    try (InputStream contents = input.getInputStream(original)) {
      contents.transferTo(output);
    }
    output.closeEntry();
  }

  static void writeEntryAs(
      final JarOutputStream output,
      final JarEntry original,
      final String outputName,
      final byte[] contents)
      throws IOException {
    output.putNextEntry(copyMetadata(original, outputName));
    output.write(contents);
    output.closeEntry();
  }

  static void copyEntry(final JarFile input, final JarOutputStream output, final JarEntry original)
      throws IOException {
    output.putNextEntry(copyMetadata(original, original.getName()));
    if (!original.isDirectory()) {
      try (InputStream contents = input.getInputStream(original)) {
        contents.transferTo(output);
      }
    }
    output.closeEntry();
  }

  private static JarEntry copyMetadata(final JarEntry original, final String outputName) {
    final JarEntry copy = new JarEntry(outputName);
    if (original.getTime() >= 0) {
      copy.setTime(original.getTime());
    }
    if (original.getComment() != null) {
      copy.setComment(original.getComment());
    }
    return copy;
  }
}
