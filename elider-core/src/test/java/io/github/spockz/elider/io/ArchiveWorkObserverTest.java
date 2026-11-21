// WHY: Verifies real core archive reads without Maven fixtures or caller annotations.

package io.github.spockz.elider.io;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import io.github.spockz.elider.model.ArtifactDigests;
import io.github.spockz.elider.model.HexDigest;
import io.github.spockz.elider.trimmer.MultiReleaseArchivePlan;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises actual core I/O, normalized paths, and listener scope lifetimes. */
@SuppressWarnings("PMD.AtLeastOneConstructor")
final class ArchiveWorkObserverTest {
  /** Keeps the valid resource-only archive isolated from other tests. */
  @TempDir private Path temporaryDirectory;

  @Test
  @SuppressWarnings("PMD.DoNotUseThreads")
  void observesCoreReadsAcrossCapturedDigestsNestedScopesAndWorkers() throws Exception {
    final Path source = temporaryDirectory.resolve("source.jar").toAbsolutePath().normalize();
    try (JarOutputStream archive = new JarOutputStream(Files.newOutputStream(source))) {
      archive.putNextEntry(new JarEntry("marker.txt"));
      archive.write(1);
      archive.closeEntry();
    }
    final Path alias = source.getParent().resolve(".").resolve(source.getFileName());
    final AtomicInteger inspections = new AtomicInteger();
    final AtomicInteger digestReads = new AtomicInteger();
    final AtomicInteger nestedReads = new AtomicInteger();
    final ArtifactDigests digests;
    final MultiReleaseArchivePlan.SourceData captured;
    try (ArchiveWorkObserver.Scope ignored =
        ArchiveWorkObserver.listen(
            new ArchiveWorkObserver.Listener() {
              @Override
              public void onSourceInspected(final Path path) {
                if (source.equals(path)) {
                  inspections.incrementAndGet();
                }
              }

              @Override
              public void onDigestRead(final Path path) {
                if (source.equals(path)) {
                  digestReads.incrementAndGet();
                }
              }
            })) {
      MultiReleaseArchivePlan.create(alias, 17, Set.of(), Set.of());
      try (ArchiveWorkObserver.Scope unused =
          ArchiveWorkObserver.listen(
              new ArchiveWorkObserver.Listener() {
                @Override
                public void onDigestRead(final Path path) {
                  if (source.equals(path)) {
                    nestedReads.incrementAndGet();
                  }
                }
              })) {
        ArtifactDigests.read(source);
      }
      MultiReleaseArchivePlan.inspectSource(source);
      digests = ArtifactDigests.read(alias);
      captured = MultiReleaseArchivePlan.inspectSource(alias, digests);
      MultiReleaseArchivePlan.create(captured, 17, Set.of(), Set.of());
      HexDigest.sha256(alias);
      try (ExecutorService executor = Executors.newSingleThreadExecutor()) {
        executor.submit(() -> MultiReleaseArchivePlan.create(source, 17, Set.of(), Set.of())).get();
      }
    }
    ArtifactDigests.read(source);

    assertAll(
        "Actual core I/O respects captured data, normalized paths, and scoped listeners",
        () -> assertEquals(4, inspections.get(), "shared plans must not reread inventory"),
        () ->
            assertEquals(
                5,
                digestReads.get(),
                "captured digests and nested or closed scopes must not add outer digest reads"),
        () -> assertEquals(1, nestedReads.get(), "nested scope must receive only its own reads"),
        () -> assertSame(digests, captured.digests(), "captured digests must be passed forward"));
  }
}
