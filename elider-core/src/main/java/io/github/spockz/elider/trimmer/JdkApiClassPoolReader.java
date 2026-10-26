/* WHY: Converts the selected JDK's documented --release signatures into ProGuard library models
 * when the active runtime's own class files are newer than the bundled Core parser supports. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;

/** Reads explicit-release APIs from ct.sym or matching runtime jmods. */
@SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops", "PMD.CommentDefaultAccessModifier"})
public final class JdkApiClassPoolReader {
  /** Minimum release accepted by the reader. */
  private static final int MIN_SUPPORTED_RELEASE = 8;

  /** Snapshot source kind backed by Java release signatures. */
  private static final String CT_SYM = "ct.sym";

  /** Snapshot source kind backed by runtime module archives. */
  private static final String JMODS = "jmods";

  /** Creates a reader for explicit compiler API releases. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JdkApiClassPoolReader() {}

  /** Reads historical signatures or exact runtime classes for the selected release. */
  public ClassPool read(final Path javaHome, final int effectiveRelease) throws IOException {
    try (JdkPlatformContext context = new JdkPlatformContext(javaHome)) {
      return read(context.snapshot(effectiveRelease));
    }
  }

  /** Reads a fresh mutable class pool from the captured snapshot. */
  public ClassPool read(final JdkPlatformContext.PlatformSnapshot snapshot) throws IOException {
    Objects.requireNonNull(snapshot, "snapshot");
    if (snapshot.effectiveRelease() < MIN_SUPPORTED_RELEASE) {
      throw new IllegalArgumentException(
          "Java release must be at least 8: " + snapshot.effectiveRelease());
    }
    if (CT_SYM.equals(snapshot.sourceKind())) {
      return CtSymClassPoolReader.read(
          snapshot.capturedFiles().getFirst(), snapshot.effectiveRelease());
    }
    if (JMODS.equals(snapshot.sourceKind())) {
      return readJmods(snapshot.capturedFiles().subList(2, snapshot.capturedFiles().size()));
    }
    throw new IOException("Unsupported captured JDK platform source: " + snapshot.sourceKind());
  }

  @SuppressWarnings({
    "PMD.CognitiveComplexity",
    "PMD.CyclomaticComplexity",
    "PMD.AvoidCatchingGenericException"
  })
  private static ClassPool readJmods(final List<JdkPlatformContext.CapturedFile> modules)
      throws IOException {
    final ClassPool classPool = new ClassPool();
    for (final JdkPlatformContext.CapturedFile module : modules) {
      try (ZipInputStream archive = new ZipInputStream(module.openJmodStream())) {
        while (true) {
          final ZipEntry entry = archive.getNextEntry();
          if (entry == null) {
            break;
          }
          if (!entry.getName().startsWith("classes/") || !entry.getName().endsWith(".class")) {
            archive.closeEntry();
            continue;
          }
          try {
            final ClassReader reader = new ClassReader(archive);
            final String name = reader.getClassName();
            if (!name.endsWith("module-info")) {
              if (classPool.getClass(name) != null) {
                throw new IOException("Duplicate runtime JDK class in jmods: " + name);
              }
              addLibraryClass(reader, classPool);
            }
          } catch (final RuntimeException exception) {
            throw new IOException(
                "Could not read captured runtime JDK class: " + entry.getName(), exception);
          }
          archive.closeEntry();
        }
      } catch (final java.util.zip.ZipException exception) {
        throw new IOException(
            "Could not read captured runtime JDK module: " + module.sourcePath(), exception);
      }
    }
    if (classPool.size() == 0) {
      throw new IOException("No runtime JDK classes found in captured jmods");
    }
    return classPool;
  }

  static void addLibraryClass(final ClassReader reader, final ClassPool classPool) {
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
}
