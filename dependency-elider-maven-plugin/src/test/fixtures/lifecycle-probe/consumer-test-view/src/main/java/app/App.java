/* WHY: Gives Elider a compiled production root that keeps only Client. */
package app;

import io.github.spockz.elider.fixture.testview.Client;

public final class App {
  public String run() {
    return new Client().value();
  }

  public static void main(final String[] args) {
    System.out.println(new App().run());
  }
}
