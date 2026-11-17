/* WHY: Initializes ProGuard references under its required serialized callback boundary. */

package io.github.spockz.elider.trimmer;

import java.util.Map;
import java.util.Set;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.kotlin.KotlinConstants;
import proguard.classfile.util.ClassReferenceInitializer;
import proguard.classfile.util.ClassSuperHierarchyInitializer;
import proguard.classfile.util.InvalidReferenceVisitor;

/** Applies ProGuard's class and hierarchy reference initializers to one pool. */
final class ProGuardReferenceInitialization {
  private ProGuardReferenceInitialization() {}

  // The default access modifier keeps pool initialization internal to the trimmer.
  // WHY: Only graph indexing invokes this phase.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void libraries(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final Set<String> platformNames,
      final InvalidReferenceVisitor invalidReferenceVisitor,
      final Map<String, RuntimeException> edgeFailures) {
    final ClassSuperHierarchyInitializer hierarchyInitializer =
        new ClassSuperHierarchyInitializer(programPool, libraryPool, invalidReferenceVisitor);
    if (libraryPool instanceof LazyPlatformClassPool lazyPool) {
      lazyPool.attachHierarchyInitializer(hierarchyInitializer);
    }
    visitClasses(
        libraryPool,
        clazz -> {
          if (!platformNames.contains(clazz.getName())) {
            clazz.accept(hierarchyInitializer);
          }
        },
        edgeFailures);
    final ClassReferenceInitializer initializer =
        new ClassReferenceInitializer(programPool, libraryPool, false, invalidReferenceVisitor);
    visitClasses(
        libraryPool,
        clazz -> {
          if (!platformNames.contains(clazz.getName())) {
            clazz.accept(initializer);
          }
        },
        edgeFailures);
  }

  // The default access modifier keeps pool initialization internal to the trimmer.
  // WHY: Only graph indexing invokes this phase.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void program(
      final ClassPool programPool,
      final ClassPool libraryPool,
      final InvalidReferenceVisitor invalidReferenceVisitor,
      final Map<String, RuntimeException> edgeFailures) {
    final ClassSuperHierarchyInitializer hierarchyInitializer =
        new ClassSuperHierarchyInitializer(programPool, libraryPool, invalidReferenceVisitor);
    if (libraryPool instanceof LazyPlatformClassPool lazyPool) {
      lazyPool.attachHierarchyInitializer(hierarchyInitializer);
    }
    visitClasses(programPool, clazz -> clazz.accept(hierarchyInitializer), edgeFailures);
    initializeClassReferences(
        programPool, programPool, libraryPool, invalidReferenceVisitor, edgeFailures);
  }

  private static void initializeClassReferences(
      final ClassPool targetPool,
      final ClassPool programPool,
      final ClassPool libraryPool,
      final InvalidReferenceVisitor invalidReferenceVisitor,
      final Map<String, RuntimeException> edgeFailures) {
    final ClassReferenceInitializer initializer =
        new ClassReferenceInitializer(programPool, libraryPool, false, invalidReferenceVisitor);
    visitClasses(targetPool, clazz -> clazz.accept(initializer), edgeFailures);
  }

  // WHY: ProGuard shares this lazy pool across class initialization callbacks.
  @SuppressWarnings({"PMD.AvoidSynchronizedStatement", "PMD.AvoidCatchingGenericException"})
  private static void visitClasses(
      final ClassPool pool,
      final java.util.function.Consumer<Clazz> visitor,
      final Map<String, RuntimeException> edgeFailures) {
    for (final Clazz clazz : pool.classes()) {
      try {
        synchronized (KotlinConstants.class) {
          visitor.accept(clazz);
        }
      } catch (final RuntimeException exception) {
        edgeFailures.putIfAbsent(
            clazz.getName(),
            ReferenceGraphIndexer.classificationFailure(clazz.getName(), exception));
      }
    }
  }
}
