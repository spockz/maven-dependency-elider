/* WHY: Main executable application invoking service worker. */

package io.github.spockz.example.reactor.app;

import io.github.spockz.example.reactor.service.ServiceWorker;

/** Main executable entrypoint for the multi-module reactor. */
public final class MainApp {

  private MainApp() {}

  /** Prints processed message to stdout. */
  @SuppressWarnings("PMD.SystemPrintln")
  public static void main(final String[] args) {
    System.out.println(ServiceWorker.processArchive("input.tar"));
  }
}
