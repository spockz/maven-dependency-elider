// WHY: Gives production code a legitimate retained provider in the partly trimmed library.

package io.github.spockz.example.testview.library;

/** Production-facing dependency API. */
public final class Client {
  private Client() {}

  /** Returns the packaged application's observable value. */
  public static String message() {
    return "client-ready";
  }
}
