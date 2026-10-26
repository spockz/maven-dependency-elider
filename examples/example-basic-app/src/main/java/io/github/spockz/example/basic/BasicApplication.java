/* WHY: Provides a runnable consumer fixture whose ZIP and JSON behavior survives dependency
 * elision.
 */

package io.github.spockz.example.basic;

import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;

/** Provides the executable entry point for the basic reference fixture. */
public final class BasicApplication {

  private BasicApplication() {}

  /** Emits the fixture's stable JSON response. */
  @SuppressWarnings("PMD.SystemPrintln")
  public static void main(String[] args) {
    if (!"hello.txt".equals(new ZipArchiveEntry("hello.txt").getName())) {
      throw new IllegalStateException("Commons Compress did not preserve the ZIP entry name");
    }
    System.out.println("{\"message\":\"hello\"}");
  }
}
