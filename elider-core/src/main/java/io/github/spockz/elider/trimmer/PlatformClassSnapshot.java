/* WHY: Detaches platform API signatures from mutable caller-owned ProGuard class definitions. */

package io.github.spockz.elider.trimmer;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.Field;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;
import proguard.classfile.Method;
import proguard.classfile.visitor.MemberVisitor;

/** Copies platform API signatures into isolated classes without Kotlin metadata. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class PlatformClassSnapshot {
  private PlatformClassSnapshot() {}

  static List<Clazz> copyOf(final ClassPool platformLibraryPool) {
    final List<Clazz> copies = new ArrayList<>();
    platformLibraryPool.classes().forEach(clazz -> copies.add(copyLibraryClass(clazz)));
    return List.copyOf(copies);
  }

  private static LibraryClass copyLibraryClass(final Clazz source) {
    if (!(source instanceof LibraryClass libraryClass)) {
      throw new IllegalArgumentException(
          "Platform class pool entries must be LibraryClass instances: " + source.getName());
    }
    if (libraryClass.kotlinMetadata != null) {
      throw new IllegalArgumentException(
          "Platform class pool entries with Kotlin metadata are unsupported: " + source.getName());
    }
    final List<LibraryField> fields = new ArrayList<>();
    final List<LibraryMethod> methods = new ArrayList<>();
    final PlatformMemberCopier memberCopier = new PlatformMemberCopier(fields, methods);
    libraryClass.fieldsAccept(memberCopier);
    libraryClass.methodsAccept(memberCopier);
    final String[] interfaces =
        IntStream.range(0, libraryClass.getInterfaceCount())
            .mapToObj(libraryClass::getInterfaceName)
            .toArray(String[]::new);
    return new LibraryClass(
        libraryClass.getAccessFlags(),
        libraryClass.getName(),
        libraryClass.getSuperName(),
        interfaces,
        null,
        0,
        null,
        fields.toArray(LibraryField[]::new),
        methods.toArray(LibraryMethod[]::new),
        null);
  }

  private record PlatformMemberCopier(List<LibraryField> fields, List<LibraryMethod> methods)
      implements MemberVisitor {
    @Override
    public void visitLibraryField(final LibraryClass owner, final LibraryField field) {
      fields.add(copyField(owner, field));
    }

    @Override
    public void visitLibraryMethod(final LibraryClass owner, final LibraryMethod method) {
      methods.add(copyMethod(owner, method));
    }

    private static LibraryField copyField(final Clazz owner, final Field field) {
      return new LibraryField(
          field.getAccessFlags(), field.getName(owner), field.getDescriptor(owner));
    }

    private static LibraryMethod copyMethod(final Clazz owner, final Method method) {
      return new LibraryMethod(
          method.getAccessFlags(), method.getName(owner), method.getDescriptor(owner));
    }
  }
}
