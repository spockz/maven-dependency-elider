/* WHY: Names the independent external inputs whose findings have separate lifecycle state. */

package io.github.spockz.elider.scanner;

/** External source partitions stored in the generic finding cache. */
public enum FindingSource {
  OSV,
  CVE_LIST
}
