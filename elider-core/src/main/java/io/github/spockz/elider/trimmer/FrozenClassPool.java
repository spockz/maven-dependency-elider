/* WHY: Keeps ProGuard's sorted pool traversal while accelerating immutable graph lookups. */

package io.github.spockz.elider.trimmer;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;

/** A graph-local pool whose membership is fixed after its index is built. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.UseConcurrentHashMap"})
final class FrozenClassPool extends ClassPool {
  /** Hash index published only after all sorted pool entries are copied. */
  private Map<String, Clazz> lookupIndex;

  /** Marks the boundary after which pool membership is immutable. */
  private boolean frozen;

  private FrozenClassPool() {
    super();
  }

  static FrozenClassPool copyOf(final ClassPool source) {
    final FrozenClassPool result = new FrozenClassPool();
    source.classNames().forEachRemaining(name -> result.addClass(name, source.getClass(name)));
    result.freeze();
    return result;
  }

  @Override
  public Clazz getClass(final String name) {
    Objects.requireNonNull(name, "name");
    if (!frozen) {
      return super.getClass(name);
    }
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
  }

  @Override
  public void removeClass(final Clazz clazz) {
    ensureMutable();
    super.removeClass(clazz);
  }

  @Override
  public Clazz removeClass(final String name) {
    ensureMutable();
    return super.removeClass(name);
  }

  @Override
  public void clear() {
    ensureMutable();
    super.clear();
  }

  private void freeze() {
    if (frozen) {
      throw new IllegalStateException("Class pool is already frozen");
    }
    final Map<String, Clazz> entries = new HashMap<>();
    super.classNames().forEachRemaining(name -> entries.put(name, super.getClass(name)));
    lookupIndex = Map.copyOf(entries);
    frozen = true;
  }

  private void ensureMutable() {
    if (frozen) {
      throw new IllegalStateException("Cannot change frozen graph class-pool membership");
    }
  }
}
