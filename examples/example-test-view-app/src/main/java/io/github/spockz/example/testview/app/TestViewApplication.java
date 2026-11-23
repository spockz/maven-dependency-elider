// WHY: Provides a packaged production entry point that only uses the retained Client class.

package io.github.spockz.example.testview.app;

import io.github.spockz.example.testview.library.Client;

/** Small application used to inspect production packaging after tests. */
public final class TestViewApplication {
  private TestViewApplication() {}

  /** Prints the production dependency result. */
  public static void main(final String[] arguments) {
    System.out.println(Client.message());
  }
}
