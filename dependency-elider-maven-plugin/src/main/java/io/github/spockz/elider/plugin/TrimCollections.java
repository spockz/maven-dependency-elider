/* WHY: Creates thread-confined map builders with the same insertion ordering
 * and default capacity as the former constructors. */

package io.github.spockz.elider.plugin;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/** Mutable map builders owned by one trim operation. */
final class TrimCollections {
  /** Twelve expected mappings select the previous constructors' capacity of sixteen. */
  private static final int DEFAULT_EXPECTED_MAPPINGS = 12;

  private TrimCollections() {}

  /* package */ static <K, V> Map<K, V> orderedMap() {
    return LinkedHashMap.newLinkedHashMap(DEFAULT_EXPECTED_MAPPINGS);
  }

  /* package */ static <K, V> Map<K, V> lookupMap() {
    return HashMap.newHashMap(DEFAULT_EXPECTED_MAPPINGS);
  }

  /* package */ static <T extends Comparable<? super T>> java.util.Set<T> sortedSet(
      final java.util.Set<T> values) {
    return java.util.Collections.unmodifiableSet(new java.util.TreeSet<>(values));
  }
}
