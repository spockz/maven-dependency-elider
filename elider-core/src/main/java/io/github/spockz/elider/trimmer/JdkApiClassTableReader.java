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
  /** Shared empty class array for unpopulated interface/subclass slots. */
  private static final Clazz[] EMPTY_CLAZZ = new Clazz[0];

  /** Shared empty field array for classes without fields. */
  private static final LibraryField[] EMPTY_FIELDS = new LibraryField[0];

  /** Shared empty method array for classes without methods. */
  private static final LibraryMethod[] EMPTY_METHODS = new LibraryMethod[0];

  /** Creates a reader for active-runtime platform snapshots. */
  public JdkApiClassTableReader() {
    // Stateless reader.
  }

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

  /** Returns a frozen, read-only JDK class table from the platform snapshot. */
  public ClassPool readFrozen(final JdkPlatformContext.PlatformSnapshot snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    return snapshot.classTableTemplate();
  }

  static ClassDeclarationCollector newDeclarationCollector() {
    return new ClassDeclarationCollector();
  }

  static FrozenClassPool populateClassTable(final List<List<LibraryClass>> moduleClasses)
      throws IOException {
    int totalClasses = 0;
    for (final List<LibraryClass> classes : moduleClasses) {
      totalClasses += classes.size();
    }
    final FrozenClassPool jdkClassTable = FrozenClassPool.mutable(totalClasses);
    for (final List<LibraryClass> classes : moduleClasses) {
      for (final LibraryClass libraryClass : classes) {
        final String name = libraryClass.getName();
        if (jdkClassTable.getClass(name) != null) {
          throw new IOException("Duplicate active runtime class in system modules: " + name);
        }
        jdkClassTable.addClass(libraryClass);
      }
    }
    if (jdkClassTable.getClass("java/lang/Object") == null) {
      throw new IOException("The active runtime platform does not contain java/lang/Object");
    }
    return jdkClassTable.freeze();
  }

  static LibraryClass parseModuleClass(
      final byte[] bytes,
      final String resource,
      final String moduleName,
      final ClassDeclarationCollector collector)
      throws IOException {
    if ("module-info.class".equals(resource) || resource.endsWith("/module-info.class")) {
      return null;
    }
    try {
      final ClassReader reader = new ClassReader(bytes);
      final String expectedName = resource.substring(0, resource.length() - ".class".length());
      final String actualName = reader.getClassName();
      if (!expectedName.equals(actualName)) {
        throw new IOException(
            "Runtime module class path does not match name: " + moduleName + "/" + resource);
      }
      return collector.readLibraryClass(reader);
    } catch (final IllegalArgumentException | IndexOutOfBoundsException exception) {
      throw new IOException(
          "Could not parse runtime module class: " + moduleName + "/" + resource, exception);
    }
  }

  /** Reusable ASM visitor that extracts LibraryClass declarations. */
  static final class ClassDeclarationCollector extends ClassVisitor {
    /** Reused field list cleared per class. */
    private final List<LibraryField> fields = new ArrayList<>();

    /** Reused method list cleared per class. */
    private final List<LibraryMethod> methods = new ArrayList<>();

    private ClassDeclarationCollector() {
      super(Opcodes.ASM9);
    }

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

    LibraryClass readLibraryClass(final ClassReader reader) {
      fields.clear();
      methods.clear();
      reader.accept(this, ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
      final String[] interfaces = reader.getInterfaces();
      final Clazz[] interfaceClasses =
          interfaces.length == 0 ? EMPTY_CLAZZ : new Clazz[interfaces.length];
      final LibraryField[] copiedFields =
          fields.isEmpty() ? EMPTY_FIELDS : fields.toArray(LibraryField[]::new);
      final LibraryMethod[] copiedMethods =
          methods.isEmpty() ? EMPTY_METHODS : methods.toArray(LibraryMethod[]::new);
      return new LibraryClass(
          reader.getAccess(),
          reader.getClassName(),
          reader.getSuperName(),
          interfaces,
          interfaceClasses,
          0,
          EMPTY_CLAZZ,
          copiedFields,
          copiedMethods,
          null);
    }
  }
}
