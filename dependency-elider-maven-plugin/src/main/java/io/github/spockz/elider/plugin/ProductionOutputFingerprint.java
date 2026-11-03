// WHY: Binds cacheable trimming to the exact production class bytes used by bytecode scanning.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.scanner.ProductionBytecodeAnalysis;
import java.io.IOException;
import java.nio.file.Path;

/** Computes a stable digest of the class files in one production output directory. */
final class ProductionOutputFingerprint {
  private ProductionOutputFingerprint() {
    throw new AssertionError("No instances");
  }

  /** Hashes the exact class files used by production bytecode scanning. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String fingerprint(final Path output) throws IOException {
    return fingerprint(output, java.util.List.of());
  }

  /** Hashes the exact class files across primary and additional output directories. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static String fingerprint(final Path output, final java.util.List<Path> additionalOutputs) throws IOException {
    return ProductionBytecodeAnalysis.fingerprint(output, additionalOutputs);
  }
}
