/* WHY: Proves concurrent cache readers see only complete fingerprint-matched records. */

package io.github.spockz.elider.cache;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ElisionDecision;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Covers atomic concurrent cache publication and lookup behavior. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.DoNotUseThreads"})
final class ElisionCacheConcurrencyTest {
  /** Isolates concurrent records from other tests. */
  @TempDir private Path temporaryDirectory;

  /** Creates the fixture before JUnit injects its temporary directory. */
  ElisionCacheConcurrencyTest() {
    // JUnit sets the temporary directory after construction.
  }

  @Test
  void readersAndWritersObserveOnlyCompleteMatchingRecords() throws Exception {
    final Path cachePath = temporaryDirectory.resolve("concurrent.bin");
    final ArtifactCoordinate retained = ArtifactCoordinate.of("g", "retained", "1");
    final ArtifactCoordinate elided = ArtifactCoordinate.of("g", "elided", "1");
    final Set<ArtifactCoordinate> inventory = Set.of(retained, elided);
    final ElisionDecision firstDecision = decision(retained, elided, 11L);
    final ElisionDecision secondDecision = decision(elided, retained, 22L);
    final ElisionCache cache = new ElisionCache();
    final CountDownLatch ready = new CountDownLatch(3);
    final CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService executor = Executors.newFixedThreadPool(3)) {
      final List<Future<?>> writers =
          List.of(
              writer(executor, ready, start, cache, cachePath, inventory, 101L, firstDecision),
              writer(executor, ready, start, cache, cachePath, inventory, 202L, secondDecision));
      final Future<?> reader =
          reader(
              executor, ready, start, cache, cachePath, inventory, firstDecision, secondDecision);
      ready.await();
      start.countDown();
      for (final Future<?> writer : writers) {
        writer.get();
      }
      reader.get();
    }
    final ElisionCache.Lookup firstLookup = cache.load(cachePath, 101L, inventory);
    final ElisionCache.Lookup secondLookup = cache.load(cachePath, 202L, inventory);
    assertThat(firstLookup.hit() ^ secondLookup.hit()).isTrue();
  }

  private static ElisionDecision decision(
      final ArtifactCoordinate retained, final ArtifactCoordinate elided, final long elapsedNanos) {
    return new ElisionDecision(
        Set.of(retained),
        Set.of(elided),
        Map.of(retained, Set.of("sample.Used"), elided, Set.of()),
        Map.of(retained, Set.of(), elided, Set.of("sample.Unused")),
        elapsedNanos);
  }

  private static Future<?> writer(
      final ExecutorService executor,
      final CountDownLatch ready,
      final CountDownLatch start,
      final ElisionCache cache,
      final Path cachePath,
      final Set<ArtifactCoordinate> inventory,
      final long fingerprint,
      final ElisionDecision decision) {
    return executor.submit(
        () -> {
          ready.countDown();
          start.await();
          for (int attempt = 0; attempt < 25; attempt++) {
            cache.store(cachePath, fingerprint, inventory, decision);
          }
          return null;
        });
  }

  private static Future<?> reader(
      final ExecutorService executor,
      final CountDownLatch ready,
      final CountDownLatch start,
      final ElisionCache cache,
      final Path cachePath,
      final Set<ArtifactCoordinate> inventory,
      final ElisionDecision firstDecision,
      final ElisionDecision secondDecision) {
    return executor.submit(
        () -> {
          ready.countDown();
          start.await();
          for (int attempt = 0; attempt < 100; attempt++) {
            assertLookup(cache.load(cachePath, 101L, inventory), firstDecision);
            assertLookup(cache.load(cachePath, 202L, inventory), secondDecision);
          }
          return null;
        });
  }

  private static void assertLookup(
      final ElisionCache.Lookup lookup, final ElisionDecision expectedDecision) {
    if (lookup.hit()) {
      assertThat(lookup.decision()).isEqualTo(expectedDecision);
    } else {
      assertThat(lookup.missReason()).isIn("missing", "fingerprint mismatch");
    }
  }
}
