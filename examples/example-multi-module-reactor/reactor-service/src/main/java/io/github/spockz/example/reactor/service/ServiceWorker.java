/* WHY: Intermediate service executing business logic via CommonHelper. */

package io.github.spockz.example.reactor.service;

import io.github.spockz.example.reactor.common.CommonHelper;

/** Intermediate service worker in the multi-module reactor. */
public final class ServiceWorker {

  private ServiceWorker() {}

  /** Executes common helper routine. */
  public static String processArchive(final String archiveName) {
    return "processed: " + CommonHelper.describeTarEntry(archiveName);
  }
}
