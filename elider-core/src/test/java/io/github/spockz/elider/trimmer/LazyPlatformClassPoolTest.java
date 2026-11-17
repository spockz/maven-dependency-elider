/* WHY: Ensures lazy JDK class-table materialization isolates templates and preserves precedence. */

package io.github.spockz.elider.trimmer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.util.ClassSuperHierarchyInitializer;

/** Tests lazy JDK class-table lookup and isolation. */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.LawOfDemeter"})
final class LazyPlatformClassPoolTest {
  /** Shared Object supertype name. */
  private static final String OBJECT_CLASS = "java/lang/Object";

  @Test
  void materializesOnlyReferencedJdkClassesAndWiresSupertypes() {
    final LibraryClass objectTemplate = new LibraryClass(0, OBJECT_CLASS, null);
    final LibraryClass listTemplate = new LibraryClass(0, "java/util/AbstractList", OBJECT_CLASS);
    final LibraryClass unusedTemplate = new LibraryClass(0, "java/sql/UnusedType", OBJECT_CLASS);
    final ClassPool jdkTable = new ClassPool();
    jdkTable.addClass(objectTemplate);
    jdkTable.addClass(listTemplate);
    jdkTable.addClass(unusedTemplate);

    final ClassPool programPool = new ClassPool();
    final Set<String> platformNames = new HashSet<>();
    final LazyPlatformClassPool pool =
        new LazyPlatformClassPool(programPool, jdkTable, platformNames);
    pool.attachHierarchyInitializer(new ClassSuperHierarchyInitializer(programPool, pool, null));

    final Clazz resolved = pool.getClass("java/util/AbstractList");

    assertAll(
        "lazy materialization resolves supertype chain without copying unused JDK classes",
        () -> assertThat(resolved).isInstanceOf(LibraryClass.class).isNotSameAs(listTemplate),
        () ->
            assertThat(((LibraryClass) resolved).superClass)
                .isNotNull()
                .isNotSameAs(objectTemplate)
                .extracting(Clazz::getName)
                .isEqualTo(OBJECT_CLASS),
        () -> assertThat(objectTemplate.subClassCount).isZero(),
        () ->
            assertThat(platformNames)
                .containsExactlyInAnyOrder("java/util/AbstractList", OBJECT_CLASS));
  }

  @Test
  void respectsSiblingAndProgramPrecedence() {
    final LibraryClass jdkShadowedBySibling = new LibraryClass(0, "fixture/Sibling", null);
    final LibraryClass jdkShadowedByProgram = new LibraryClass(0, "fixture/Program", null);
    final ClassPool jdkTable = new ClassPool();
    jdkTable.addClass(jdkShadowedBySibling);
    jdkTable.addClass(jdkShadowedByProgram);

    final LibraryClass siblingClass = new LibraryClass(0, "fixture/Sibling", null);
    final LibraryClass programClass = new LibraryClass(0, "fixture/Program", null);
    final ClassPool programPool = new ClassPool(programClass);
    final Set<String> platformNames = new HashSet<>();
    final LazyPlatformClassPool pool =
        new LazyPlatformClassPool(programPool, jdkTable, platformNames);
    pool.addClass(siblingClass);

    assertAll(
        () -> assertThat(pool.getClass("fixture/Sibling")).isSameAs(siblingClass),
        () -> assertThat(pool.getClass("fixture/Program")).isNull(),
        () -> assertThat(platformNames).isEmpty());
  }
}
