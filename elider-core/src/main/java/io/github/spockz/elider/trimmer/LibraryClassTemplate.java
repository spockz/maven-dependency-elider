/* WHY: Stores immutable symbolic library declarations for fresh graph-local ProGuard classes. */

package io.github.spockz.elider.trimmer;

import java.util.ArrayList;
import java.util.List;
import proguard.classfile.Clazz;
import proguard.classfile.Field;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;
import proguard.classfile.Method;
import proguard.classfile.visitor.MemberVisitor;

/** Symbolic declarations without initialized ProGuard references. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
record LibraryClassTemplate(
    String name,
    int accessFlags,
    String superName,
    List<String> interfaceNames,
    List<MemberTemplate> fields,
    List<MemberTemplate> methods) {
  LibraryClassTemplate {
    interfaceNames = List.copyOf(interfaceNames);
    fields = List.copyOf(fields);
    methods = List.copyOf(methods);
  }

  /** Captures the declarations used by ProGuard's reference initializers. */
  @SuppressWarnings("PMD.LawOfDemeter")
  static LibraryClassTemplate from(final LibraryClass source) {
    final List<MemberTemplate> fields = new ArrayList<>();
    final List<MemberTemplate> methods = new ArrayList<>();
    final MemberTemplateCollector collector = new MemberTemplateCollector(fields, methods);
    source.fieldsAccept(collector);
    source.methodsAccept(collector);
    final List<String> interfaces = new ArrayList<>();
    for (final String interfaceName : source.interfaceNames) {
      interfaces.add(interfaceName);
    }
    return new LibraryClassTemplate(
        source.getName(),
        source.getAccessFlags(),
        source.getSuperName(),
        interfaces,
        fields,
        methods);
  }

  /** Creates a fresh mutable ProGuard class and all of its declaration arrays. */
  LibraryClass materialize() {
    final String[] interfaces = interfaceNames.toArray(String[]::new);
    final LibraryField[] materializedFields =
        fields.stream()
            .map(
                member ->
                    new LibraryField(member.accessFlags(), member.name(), member.descriptor()))
            .toArray(LibraryField[]::new);
    final LibraryMethod[] materializedMethods =
        methods.stream()
            .map(
                member ->
                    new LibraryMethod(member.accessFlags(), member.name(), member.descriptor()))
            .toArray(LibraryMethod[]::new);
    return new LibraryClass(
        accessFlags,
        name,
        superName,
        interfaces,
        new Clazz[interfaces.length],
        0,
        new Clazz[0],
        materializedFields,
        materializedMethods,
        null);
  }

  /** Symbolic declaration of one field or method. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record MemberTemplate(int accessFlags, String name, String descriptor) {}

  private record MemberTemplateCollector(List<MemberTemplate> fields, List<MemberTemplate> methods)
      implements MemberVisitor {
    @Override
    public void visitLibraryField(final LibraryClass owner, final LibraryField field) {
      fields.add(template(owner, field));
    }

    @Override
    public void visitLibraryMethod(final LibraryClass owner, final LibraryMethod method) {
      methods.add(template(owner, method));
    }

    private static MemberTemplate template(final Clazz owner, final Field field) {
      return new MemberTemplate(
          field.getAccessFlags(), field.getName(owner), field.getDescriptor(owner));
    }

    private static MemberTemplate template(final Clazz owner, final Method method) {
      return new MemberTemplate(
          method.getAccessFlags(), method.getName(owner), method.getDescriptor(owner));
    }
  }
}
