/* WHY: Builds a fresh library pool from captured ct.sym bytes. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.objectweb.asm.ClassReader;
import proguard.classfile.ClassPool;

/** Builds one mutable ProGuard pool from the selected ct.sym release. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class CtSymClassPoolReader {
  private CtSymClassPoolReader() {}

  static ClassPool read(final JdkPlatformContext.CapturedFile source, final int release)
      throws IOException {
    final String releaseCode = releaseCode(release);
    final ClassPool classPool = new ClassPool();
    try (ZipInputStream archive = new ZipInputStream(source.openStream())) {
      while (true) {
        final ZipEntry entry = archive.getNextEntry();
        if (entry == null) {
          break;
        }
        readEntry(archive, entry, releaseCode, release, classPool);
        archive.closeEntry();
      }
    } catch (final java.util.zip.ZipException exception) {
      throw new IOException(
          "Could not read captured JDK API archive: " + source.sourcePath(), exception);
    }
    if (classPool.size() == 0) {
      throw new IOException(
          "No captured JDK API signatures were found for --release "
              + release
              + " in "
              + source.sourcePath());
    }
    return classPool;
  }

  private static void readEntry(
      final ZipInputStream archive,
      final ZipEntry entry,
      final String releaseCode,
      final int release,
      final ClassPool classPool)
      throws IOException {
    final String internalName = signatureClassName(entry, releaseCode);
    if (internalName == null) {
      return;
    }
    if (classPool.getClass(internalName) != null) {
      throw new IOException(
          "Multiple ct.sym signatures match Java " + release + " for class " + internalName);
    }
    final ClassReader reader = readSignature(archive, entry);
    if (!internalName.equals(className(reader, entry))) {
      throw new IOException("ct.sym class path does not match class name: " + entry.getName());
    }
    addSignature(reader, entry, classPool);
  }

  private static String signatureClassName(final ZipEntry entry, final String releaseCode) {
    final String[] pathParts = entry.getName().split("/", 3);
    if (pathParts.length != 3
        || !pathParts[0].contains(releaseCode)
        || !pathParts[2].endsWith(".sig")) {
      return null;
    }
    final String internalName = pathParts[2].substring(0, pathParts[2].length() - 4);
    return internalName.endsWith("module-info") ? null : internalName;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static String className(final ClassReader reader, final ZipEntry entry)
      throws IOException {
    try {
      return reader.getClassName();
    } catch (final RuntimeException exception) {
      throw new IOException("Could not read JDK API signature: " + entry.getName(), exception);
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static ClassReader readSignature(final ZipInputStream archive, final ZipEntry entry)
      throws IOException {
    try {
      return new ClassReader(archive);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not read JDK API signature: " + entry.getName(), exception);
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void addSignature(
      final ClassReader reader, final ZipEntry entry, final ClassPool classPool)
      throws IOException {
    try {
      JdkApiClassPoolReader.addLibraryClass(reader, classPool);
    } catch (final RuntimeException exception) {
      throw new IOException("Could not read JDK API signature: " + entry.getName(), exception);
    }
  }

  private static String releaseCode(final int release) {
    return release <= 9
        ? Integer.toString(release)
        : Character.toString((char) ('A' + release - 10));
  }
}
