/* WHY: Keeps ProGuard's sorted pool traversal while accelerating immutable graph lookups. */

package io.github.spockz.elider.trimmer;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.LibraryClass;

/** A graph-local pool whose membership is fixed after its index is built. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
final class FrozenClassPool extends ClassPool {
  /** Hash index populated incrementally while mutable so freeze() is O(1). */
  private final Map<String, Clazz> lookupIndex;

  /** Marks the boundary after which pool membership is immutable. */
  private boolean frozen;

  /** Tracks whether every entry is a plain LibraryClass without Kotlin metadata. */
  private boolean plainLibraryClassesOnly = true;

  private FrozenClassPool(final int expectedSize) {
    super();
    lookupIndex = expectedSize > 0 ? HashMap.newHashMap(expectedSize) : new HashMap<>();
  }

  static FrozenClassPool mutable() {
    return new FrozenClassPool(0);
  }

  static FrozenClassPool mutable(final int expectedSize) {
    return new FrozenClassPool(expectedSize);
  }

  static FrozenClassPool copyOf(final ClassPool source) {
    final FrozenClassPool result = new FrozenClassPool(source.size());
    source.classes().forEach(result::addClass);
    return result.freeze();
  }

  static FrozenClassPool copyOf(final Iterable<Clazz> classes) {
    final int expectedSize =
        classes instanceof Collection<Clazz> collection ? collection.size() : 0;
    final FrozenClassPool result = new FrozenClassPool(expectedSize);
    for (final Clazz clazz : classes) {
      result.addClass(clazz);
    }
    return result.freeze();
  }

  @Override
  public Clazz getClass(final String name) {
    Objects.requireNonNull(name, "name");
    return lookupIndex.get(name);
  }

  @Override
  public void addClass(final Clazz clazz) {
    ensureMutable();
    super.addClass(clazz);
  }

  @Override
  public void addClass(final String name, final Clazz clazz) {
    ensureMutable();
    super.addClass(name, clazz);
    lookupIndex.put(name, clazz);
    if (!(clazz instanceof LibraryClass libraryClass) || libraryClass.kotlinMetadata != null) {
      plainLibraryClassesOnly = false;
    }
  }

  @Override
  public void removeClass(final Clazz clazz) {
    ensureMutable();
    super.removeClass(clazz);
  }

  @Override
  public Clazz removeClass(final String name) {
    ensureMutable();
    final Clazz removed = super.removeClass(name);
    lookupIndex.remove(name);
    return removed;
  }

  @Override
  public void clear() {
    ensureMutable();
    super.clear();
    lookupIndex.clear();
    plainLibraryClassesOnly = true;
  }

  boolean isPlainLibraryClassesOnly() {
    return plainLibraryClassesOnly;
  }

  FrozenClassPool freeze() {
    if (frozen) {
      throw new IllegalStateException("Class pool is already frozen");
    }
    frozen = true;
    return this;
  }

  private void ensureMutable() {
    if (frozen) {
      throw new IllegalStateException("Cannot change frozen graph class-pool membership");
    }
  }
}
