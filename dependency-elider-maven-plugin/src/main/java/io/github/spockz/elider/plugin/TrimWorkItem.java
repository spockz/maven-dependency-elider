/* WHY: Allows independent worker tasks to report checked I/O failures
 * without losing the original cause. */

package io.github.spockz.elider.plugin;

import java.io.IOException;

/** Computes one independent item with explicit checked failures. */
@FunctionalInterface
interface TrimWorkItem<T, R> {
  /** Computes one item and reports checked failures without hiding their causes. */
  R execute(T item) throws IOException;
}
