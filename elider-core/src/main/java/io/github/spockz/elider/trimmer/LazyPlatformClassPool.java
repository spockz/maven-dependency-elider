/* WHY: Materializes only referenced JDK classes instead of cloning the full JDK table. */

package io.github.spockz.elider.trimmer;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;
import proguard.classfile.util.ClassSuperHierarchyInitializer;

/** Library pool that lazily clones JDK class templates on demand. */
// WHY: Graph indexing uses one pool per candidate on a single thread.
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class LazyPlatformClassPool extends ClassPool {
  /** Program pool whose classes shadow JDK classes of the same name. */
  private final ClassPool programPool;

  /** Read-only JDK class templates. */
  private final ClassPool jdkClassTable;

  /** Optional read-only sibling class templates shared across a tier. */
  private final ClassPool siblingTemplates;

  /** Tracks materialized JDK class names so indexing skips them as library roots. */
  private final Set<String> platformNames;

  /** O(1) lookup for sibling library classes added before indexing. */
  private final Map<String, Clazz> siblingLookup = new HashMap<>();

  /** O(1) lookup for JDK classes materialized during this graph build. */
  private final Map<String, Clazz> materializedPlatform = new HashMap<>();

  /** Initializes superClass and interfaceClasses on newly materialized JDK classes. */
  private ClassSuperHierarchyInitializer hierarchyInitializer;

  LazyPlatformClassPool(
      final ClassPool programPool, final ClassPool jdkClassTable, final Set<String> platformNames) {
    this(programPool, jdkClassTable, null, platformNames);
  }

  LazyPlatformClassPool(
      final ClassPool programPool,
      final ClassPool jdkClassTable,
      final ClassPool siblingTemplates,
      final Set<String> platformNames) {
    super();
    this.programPool = Objects.requireNonNull(programPool, "programPool");
    this.jdkClassTable = Objects.requireNonNull(jdkClassTable, "jdkClassTable");
    this.siblingTemplates = siblingTemplates;
    this.platformNames = Objects.requireNonNull(platformNames, "platformNames");
  }

  void attachHierarchyInitializer(final ClassSuperHierarchyInitializer initializer) {
    this.hierarchyInitializer = Objects.requireNonNull(initializer, "initializer");
  }

  boolean hasClass(final String name) {
    return siblingLookup.containsKey(name)
        || materializedPlatform.containsKey(name)
        || (programPool.getClass(name) == null
            && ((siblingTemplates != null && siblingTemplates.getClass(name) != null)
                || jdkClassTable.getClass(name) != null));
  }

  @Override
  public void addClass(final String name, final Clazz clazz) {
    super.addClass(name, clazz);
    siblingLookup.put(name, clazz);
  }

  @Override
  public Clazz removeClass(final String name) {
    siblingLookup.remove(name);
    return super.removeClass(name);
  }

  @Override
  public void clear() {
    siblingLookup.clear();
    materializedPlatform.clear();
    platformNames.clear();
    super.clear();
  }

  @Override
  public Clazz getClass(final String name) {
    Objects.requireNonNull(name, "name");
    final Clazz sibling = siblingLookup.get(name);
    if (sibling != null) {
      return sibling;
    }
    final Clazz materialized = materializedPlatform.get(name);
    if (materialized != null) {
      return materialized;
    }
    if (programPool.getClass(name) != null) {
      return null;
    }
    final LibraryClass siblingCopy = materializeSibling(name);
    if (siblingCopy != null) {
      return siblingCopy;
    }
    final Clazz template = jdkClassTable.getClass(name);
    if (template == null) {
      return null;
    }
    final LibraryClass copy = PlatformClassSnapshot.copyLibraryClass(template);
    materializedPlatform.put(name, copy);
    platformNames.add(name);
    if (hierarchyInitializer != null) {
      copy.accept(hierarchyInitializer);
    }
    return copy;
  }

  private LibraryClass materializeSibling(final String name) {
    if (siblingTemplates == null) {
      return null;
    }
    final Clazz siblingTemplate = siblingTemplates.getClass(name);
    if (siblingTemplate == null) {
      return null;
    }
    final LibraryClass copy =
        PlatformClassSnapshot.copyLibraryClassPreservingKotlin(siblingTemplate);
    siblingLookup.put(name, copy);
    if (hierarchyInitializer != null) {
      copy.accept(hierarchyInitializer);
    }
    return copy;
  }
}
