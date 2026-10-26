/* WHY: Builds a fresh library pool from selected ct.sym entries after a cache miss. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import proguard.classfile.ClassPool;

/** Builds one mutable ProGuard pool from the selected ct.sym release. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class CtSymClassPoolReader {
  private CtSymClassPoolReader() {}

  static ClassPool read(final Path source, final int release) throws IOException {
    final String releaseCode = releaseCode(release);
    final ClassPool classPool = new ClassPool();
    try (ZipFile archive = new ZipFile(source.toFile())) {
      final Enumeration<? extends ZipEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        readEntry(archive, entries.nextElement(), releaseCode, release, classPool);
      }
    } catch (final ZipException exception) {
      throw new IOException("Could not read JDK API archive: " + source, exception);
    }
    if (classPool.size() == 0) {
      throw new IOException(
          "No JDK API signatures were found for --release " + release + " in " + source);
    }
    return classPool;
  }

  private static void readEntry(
      final ZipFile archive,
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
  private static ClassReader readSignature(final ZipFile archive, final ZipEntry entry)
      throws IOException {
    try (InputStream signature = archive.getInputStream(entry)) {
      return new ClassReader(signature);
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
