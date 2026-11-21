// WHY: Gives both policies a baseline without either selected call in production bytecode.

package io.github.spockz.example.forbidden;

/** Runs the safe Commons Compress operation with a plain value. */
public final class PlainApplication {
  private PlainApplication() {}

  /** Prints the same value as the decode and stream variants. */
  public static void main(final String[] args) {
    System.out.println(ArchiveExample.entry().getName() + ": hello");
  }
}
