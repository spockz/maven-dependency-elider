// WHY: Captures bounded compiler class outputs by physical path and content digest.

package io.github.spockz.elider.correspondence;

import io.github.spockz.elider.correspondence.SourceReproductionResult.ClassEntry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/** Reads one isolated javac output directory and rejects non-class outputs. */
final class SourceClassOutputInventory {
  /** Required suffix for javac output files. */
  private static final String CLASS_SUFFIX = ".class";

  /** Multi-release class output is outside the supported single-tier inventory. */
  private static final String VERSIONED_ENTRIES = "META-INF/versions/";

  /** Aggregate limit across every isolated compilation task. */
  private static final int MAX_CLASS_COUNT = 100_000;

  /** Aggregate output bound across all source units in one reproduction. */
  private static final long MAX_OUTPUT_BYTES = 512L * 1024 * 1024;

  private SourceClassOutputInventory() {}

  /* default */ static Inventory read(final Path output) throws IOException {
    final List<ClassEntry> classes = new ArrayList<>();
    long totalBytes = 0;
    try (Stream<Path> paths = Files.walk(output)) {
      for (final Path file : paths.filter(Files::isRegularFile).toList()) {
        final String path = output.relativize(file).toString().replace('\\', '/');
        validateOutputPath(path);
        totalBytes += Files.size(file);
        validateOutputBounds(classes.size(), totalBytes);
        classes.add(new ClassEntry(path, SourceFileDigest.sha256(file)));
      }
    }
    classes.sort(Comparator.comparing(ClassEntry::path));
    return new Inventory(List.copyOf(classes), totalBytes);
  }

  /* default */ static void requireAggregateBounds(final int classCount, final long totalBytes)
      throws IOException {
    if (classCount > MAX_CLASS_COUNT || totalBytes > MAX_OUTPUT_BYTES) {
      throw new IOException("Aggregate compiler output exceeds supported count or size");
    }
  }

  private static void validateOutputPath(final String path) throws IOException {
    if (!path.endsWith(CLASS_SUFFIX)
        || path.startsWith(VERSIONED_ENTRIES)
        || path.endsWith("module-info.class")) {
      throw new IOException("Compiler emitted an unsupported output: " + path);
    }
  }

  private static void validateOutputBounds(final int classCount, final long totalBytes)
      throws IOException {
    if (classCount >= MAX_CLASS_COUNT || totalBytes > MAX_OUTPUT_BYTES) {
      throw new IOException("Compiler output exceeds supported class count or size");
    }
  }

  /* default */ record Inventory(List<ClassEntry> classes, long totalBytes) {
    Inventory {
      classes = List.copyOf(classes);
    }
  }
}
