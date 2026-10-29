/* WHY: Converts the selected JDK's documented --release signatures into ProGuard library models
 * when the active runtime's own class files are newer than the bundled Core parser supports. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
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
          snapshot.sourceIdentities().getFirst().sourcePath(), snapshot.effectiveRelease());
    }
    if (JMODS.equals(snapshot.sourceKind())) {
      return readJmods(snapshot.sourceIdentities().subList(2, snapshot.sourceIdentities().size()));
    }
    throw new IOException("Unsupported selected JDK platform source: " + snapshot.sourceKind());
  }

  /** Reads platform signatures into a fixed-membership pool. */
  public ClassPool readFrozen(final JdkPlatformContext.PlatformSnapshot snapshot)
      throws IOException {
    return FrozenClassPool.copyOf(read(snapshot));
  }

  private static ClassPool readJmods(final List<JdkPlatformContext.SourceIdentity> modules)
      throws IOException {
    final ClassPool classPool = new ClassPool();
    for (final JdkPlatformContext.SourceIdentity module : modules) {
      PlatformArchiveInspector.validateJmodHeader(module.sourcePath());
      try (ZipFile archive = new ZipFile(module.sourcePath().toFile())) {
        final Enumeration<? extends ZipEntry> entries = archive.entries();
        while (entries.hasMoreElements()) {
          final ZipEntry entry = entries.nextElement();
          if (!entry.getName().startsWith("classes/") || !entry.getName().endsWith(".class")) {
            continue;
          }
          readJmodClass(archive, entry, classPool);
        }
      } catch (final ZipException exception) {
        throw new IOException(
            "Could not read runtime JDK module: " + module.sourcePath(), exception);
      }
    }
    if (classPool.size() == 0) {
      throw new IOException("No runtime JDK classes found in captured jmods");
    }
    return classPool;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static void readJmodClass(
      final ZipFile archive, final ZipEntry entry, final ClassPool classPool) throws IOException {
    try (InputStream classFile = archive.getInputStream(entry)) {
      final ClassReader reader = new ClassReader(classFile);
      final String name = reader.getClassName();
      if (!name.endsWith("module-info")) {
        if (classPool.getClass(name) != null) {
          throw new IOException("Duplicate runtime JDK class in jmods: " + name);
        }
        addLibraryClass(reader, classPool);
      }
    } catch (final RuntimeException exception) {
      throw new IOException("Could not parse runtime JDK class: " + entry.getName(), exception);
    }
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
