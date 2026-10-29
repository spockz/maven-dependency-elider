/* WHY: Provides a traceable application root for the MRJAR example fixture. */

package io.github.spockz.example.mrjar;

import io.github.spockz.example.mrjar.dependency.MultiReleaseService;

/** Prints the implementation selected by the running JDK. */
public final class MultiReleaseApplication {

  /** Runs the dependency's effective MRJAR implementation. */
  public static void main(final String[] arguments) {
    System.out.println(MultiReleaseService.value());
  }
}
