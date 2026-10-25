/* WHY: Converts the selected JDK's documented --release signatures into ProGuard library models
 * when the active runtime's own class files are newer than the bundled Core parser supports. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;

/** Reads explicit-release APIs from ct.sym or matching runtime jmods. */
@SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
public final class JdkApiClassPoolReader {
  /** Minimum release accepted by the reader. */
  private static final int MIN_SUPPORTED_RELEASE = 8;

  /** Creates a reader for explicit compiler API releases. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JdkApiClassPoolReader() {}

  /** Reads historical signatures or exact runtime classes for the selected release. */
  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.ExceptionAsFlowControl"
  })
  public ClassPool read(final Path javaHome, final int effectiveRelease) throws IOException {
    Objects.requireNonNull(javaHome, "javaHome");
    if (effectiveRelease < MIN_SUPPORTED_RELEASE) {
      throw new IllegalArgumentException("Java release must be at least 8: " + effectiveRelease);
    }
    final Path ctSym = javaHome.resolve("lib/ct.sym");
    if (!Files.isRegularFile(ctSym)) {
      throw new IOException("The selected JDK does not provide lib/ct.sym: " + ctSym);
    }

    final String releaseCode = releaseCode(effectiveRelease);
    final ClassPool classPool = new ClassPool();
    try (ZipFile archive = new ZipFile(ctSym.toFile())) {
      final Enumeration<? extends ZipEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final ZipEntry entry = entries.nextElement();
        final String[] pathParts = entry.getName().split("/", 3);
        if (pathParts.length != 3
            || !pathParts[0].contains(releaseCode)
            || !pathParts[2].endsWith(".sig")) {
          continue;
        }
        final String internalName =
            pathParts[2].substring(0, pathParts[2].length() - ".sig".length());
        if (internalName.endsWith("module-info")) {
          continue;
        }
        if (classPool.getClass(internalName) != null) {
          throw new IOException(
              "Multiple ct.sym signatures match Java "
                  + effectiveRelease
                  + " for class "
                  + internalName);
        }
        try (java.io.InputStream input = archive.getInputStream(entry)) {
          final ClassReader reader = new ClassReader(input);
          if (!internalName.equals(reader.getClassName())) {
            throw new IllegalArgumentException("ct.sym class path does not match class name");
          }
          addLibraryClass(reader, classPool);
        } catch (final IllegalArgumentException exception) {
          throw new IOException("Could not read JDK API signature: " + entry.getName(), exception);
        }
      }
    }
    if (classPool.size() == 0) {
      if (readJdkRelease(javaHome) == effectiveRelease) {
        return readJmods(javaHome);
      }
      throw new IOException(
          "No JDK API signatures were found for --release " + effectiveRelease + " in " + ctSym);
    }
    return classPool;
  }

  @SuppressWarnings({"PMD.CognitiveComplexity", "PMD.CyclomaticComplexity"})
  private static ClassPool readJmods(final Path javaHome) throws IOException {
    final Path jmods = javaHome.resolve("jmods");
    if (!Files.isDirectory(jmods)) {
      throw new IOException("The selected JDK has no jmods directory: " + jmods);
    }
    final ClassPool classPool = new ClassPool();
    try (java.util.stream.Stream<Path> paths = Files.list(jmods)) {
      for (final Path jmod : paths.filter(path -> path.toString().endsWith(".jmod")).toList()) {
        try (ZipFile archive = new ZipFile(jmod.toFile())) {
          final Enumeration<? extends ZipEntry> entries = archive.entries();
          while (entries.hasMoreElements()) {
            final ZipEntry entry = entries.nextElement();
            if (!entry.getName().startsWith("classes/") || !entry.getName().endsWith(".class")) {
              continue;
            }
            try (java.io.InputStream input = archive.getInputStream(entry)) {
              final ClassReader reader = new ClassReader(input);
              final String name = reader.getClassName();
              if (!name.endsWith("module-info")) {
                if (classPool.getClass(name) != null) {
                  throw new IOException("Duplicate runtime JDK class in jmods: " + name);
                }
                addLibraryClass(reader, classPool);
              }
            }
          }
        }
      }
    }
    if (classPool.size() == 0) {
      throw new IOException("No runtime JDK classes found in " + jmods);
    }
    return classPool;
  }

  private static int readJdkRelease(final Path javaHome) throws IOException {
    final Path releaseFile = javaHome.resolve("release");
    if (!Files.isRegularFile(releaseFile)) {
      return -1;
    }
    for (final String line : Files.readAllLines(releaseFile)) {
      if (line.startsWith("JAVA_VERSION=")) {
        final String version = line.substring("JAVA_VERSION=\"".length()).replace("\"", "");
        final int separator = version.indexOf('.');
        final String feature = separator < 0 ? version : version.substring(0, separator);
        try {
          return Integer.parseInt(feature);
        } catch (final NumberFormatException exception) {
          throw new IOException("Invalid JAVA_VERSION in " + releaseFile, exception);
        }
      }
    }
    return -1;
  }

  private static void addLibraryClass(final ClassReader reader, final ClassPool classPool) {
    final List<LibraryField> fields = new ArrayList<>();
    final List<LibraryMethod> methods = new ArrayList<>();
    reader.accept(
        new ClassVisitor(Opcodes.ASM9) {
          @Override
          public org.objectweb.asm.FieldVisitor visitField(
              final int access,
              final String name,
              final String descriptor,
              final String signature,
              final Object value) {
            fields.add(new LibraryField(access, name, descriptor));
            return null;
          }

          @Override
          public org.objectweb.asm.MethodVisitor visitMethod(
              final int access,
              final String name,
              final String descriptor,
              final String signature,
              final String[] exceptions) {
            methods.add(new LibraryMethod(access, name, descriptor));
            return null;
          }
        },
        ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    final String[] interfaces = reader.getInterfaces();
    classPool.addClass(
        new LibraryClass(
            reader.getAccess(),
            reader.getClassName(),
            reader.getSuperName(),
            interfaces,
            new Clazz[interfaces.length],
            0,
            new Clazz[0],
            fields.toArray(LibraryField[]::new),
            methods.toArray(LibraryMethod[]::new),
            null));
  }

  private static String releaseCode(final int release) {
    return release <= 9
        ? Integer.toString(release)
        : Character.toString((char) ('A' + release - 10));
  }
}
