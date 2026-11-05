// WHY: Keeps one safe dependency class reachable through the real Maven compiler and elider.

package org.example.consumer;

import org.example.fixture.Safe;

public final class App {
  private App() {}

  public static void main(final String[] arguments) {
    Safe.safe();
  }
}
