/* WHY: Provides a common utility referencing commons-compress while omitting commons-codec references. */

package io.github.spockz.example.reactor.common;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;

/** Common utility helper used across reactor modules. */
public final class CommonHelper {

  private CommonHelper() {}

  /** Creates a test tar entry name to exercise commons-compress without referencing commons-codec. */
  public static String describeTarEntry(final String name) {
    final TarArchiveEntry entry = new TarArchiveEntry(name);
    return entry.getName();
  }
}
