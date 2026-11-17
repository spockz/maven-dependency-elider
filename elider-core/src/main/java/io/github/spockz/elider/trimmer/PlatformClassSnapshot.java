/* WHY: Detaches platform API signatures from mutable caller-owned ProGuard class definitions. */

package io.github.spockz.elider.trimmer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.LibraryField;
import proguard.classfile.LibraryMethod;

/** Copies platform API signatures into isolated classes without Kotlin metadata. */
// WHY: ProGuard LibraryClass exposes public member arrays.
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.LawOfDemeter"})
final class PlatformClassSnapshot {
  /** Shared empty class-name array for classes without interfaces. */
  private static final String[] EMPTY_STRINGS = new String[0];

  /** Shared empty class array for unpopulated interface/subclass slots. */
  private static final Clazz[] EMPTY_CLAZZ = new Clazz[0];

  /** Shared empty field array for classes without fields. */
  private static final LibraryField[] EMPTY_FIELDS = new LibraryField[0];

  /** Shared empty method array for classes without methods. */
  private static final LibraryMethod[] EMPTY_METHODS = new LibraryMethod[0];

  private PlatformClassSnapshot() {}

  static List<Clazz> copyOf(final ClassPool jdkClassTable) {
    final List<Clazz> copies = new ArrayList<>(jdkClassTable.size());
    for (final Clazz clazz : jdkClassTable.classes()) {
      copies.add(copyLibraryClass(clazz));
    }
    return Collections.unmodifiableList(copies);
  }

  /* default */ static LibraryClass copyLibraryClass(final Clazz source) {
    return copyLibraryClass(source, true);
  }

  private static LibraryClass copyLibraryClass(
      final Clazz source, final boolean rejectKotlinMetadata) {
    final LibraryClass libraryClass = validateLibraryTemplate(source, rejectKotlinMetadata);
    final String[] interfaces = copyInterfaceNames(libraryClass);
    final Clazz[] interfaceClasses =
        interfaces.length == 0 ? EMPTY_CLAZZ : new Clazz[interfaces.length];
    return new LibraryClass(
        libraryClass.getAccessFlags(),
        libraryClass.getName(),
        libraryClass.getSuperName(),
        interfaces,
        interfaceClasses,
        0,
        EMPTY_CLAZZ,
        copyFields(libraryClass),
        copyMethods(libraryClass),
        rejectKotlinMetadata ? null : libraryClass.kotlinMetadata);
  }

  private static LibraryClass validateLibraryTemplate(
      final Clazz source, final boolean rejectKotlinMetadata) {
    if (!(source instanceof LibraryClass libraryClass)) {
      throw new IllegalArgumentException(
          "JDK class table entries must be LibraryClass instances: " + source.getName());
    }
    if (rejectKotlinMetadata && libraryClass.kotlinMetadata != null) {
      throw new IllegalArgumentException(
          "JDK class table entries with Kotlin metadata are unsupported: " + source.getName());
    }
    return libraryClass;
  }

  private static String[] copyInterfaceNames(final LibraryClass libraryClass) {
    final String[] sourceInterfaces = libraryClass.interfaceNames;
    return sourceInterfaces == null || sourceInterfaces.length == 0
        ? EMPTY_STRINGS
        : sourceInterfaces.clone();
  }

  /* default */ static LibraryClass copyLibraryClassPreservingKotlin(final Clazz source) {
    return copyLibraryClass(source, false);
  }

  private static LibraryField[] copyFields(final LibraryClass owner) {
    final LibraryField[] source = owner.fields;
    if (source == null || source.length == 0) {
      return EMPTY_FIELDS;
    }
    final LibraryField[] copy = new LibraryField[source.length];
    for (int index = 0; index < source.length; index++) {
      final LibraryField field = source[index];
      copy[index] =
          new LibraryField(
              field.getAccessFlags(), field.getName(owner), field.getDescriptor(owner));
    }
    return copy;
  }

  private static LibraryMethod[] copyMethods(final LibraryClass owner) {
    final LibraryMethod[] source = owner.methods;
    if (source == null || source.length == 0) {
      return EMPTY_METHODS;
    }
    final LibraryMethod[] copy = new LibraryMethod[source.length];
    for (int index = 0; index < source.length; index++) {
      final LibraryMethod method = source[index];
      copy[index] =
          new LibraryMethod(
              method.getAccessFlags(), method.getName(owner), method.getDescriptor(owner));
    }
    return copy;
  }
}
