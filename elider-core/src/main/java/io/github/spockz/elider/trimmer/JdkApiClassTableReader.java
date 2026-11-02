/* WHY: Materializes isolated ProGuard class tables from parsed active-runtime module classes. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.Opcodes;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;

/** Reads isolated JDK class tables from one captured active-runtime snapshot. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
public final class JdkApiClassTableReader {
  /** Creates a reader for active-runtime platform snapshots. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public JdkApiClassTableReader() {}

  /** Creates a fresh mutable class table from the active runtime. */
  public ClassPool read() throws IOException {
    try (JdkPlatformContext context = new JdkPlatformContext()) {
      return read(context.snapshot());
    }
  }

  /** Reads a fresh mutable JDK class table from captured class templates. */
  public ClassPool read(final JdkPlatformContext.PlatformSnapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    final ClassPool jdkClassTable = new ClassPool();
    for (final Clazz clazz : PlatformClassSnapshot.copyOf(snapshot.classTableTemplate())) {
      jdkClassTable.addClass(clazz);
    }
    return jdkClassTable;
  }

  /** Reads a fresh table whose membership cannot be changed by an analysis. */
  public ClassPool readFrozen(final JdkPlatformContext.PlatformSnapshot snapshot) {
    return FrozenClassPool.copyOf(read(snapshot));
  }

  static void addLibraryClass(final ClassReader reader, final ClassPool jdkClassTable) {
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
    jdkClassTable.addClass(
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
