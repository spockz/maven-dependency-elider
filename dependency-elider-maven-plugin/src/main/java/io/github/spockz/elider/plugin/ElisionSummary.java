// WHY: Keeps analysis and mutation goals honest about counts and evidence they do not produce.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ElisionDecision;
import java.util.Locale;
import org.apache.maven.plugin.logging.Log;

/** Emits only whole-artifact results supported by the current pipeline. */
final class ElisionSummary {
  /** Prevents instances of this static-only writer. */
  private ElisionSummary() {
    throw new AssertionError("No instances");
  }

  /** Prints whole-artifact counts and explicitly marks unsupported stages. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static void report(final Log log, final ElisionDecision decision, final int inputCount) {
    if (!log.isInfoEnabled()) {
      return;
    }
    final int removed = decision.elidedArtifacts().size();
    final String percentage =
        inputCount == 0
            ? "N/A"
            : String.format(Locale.ROOT, "%.1f%%", removed * 100.0 / inputCount);
    log.info("Dependency Elider summary");
    log.info("  Whole artifacts: " + removed + " / " + inputCount + " (" + percentage + ")");
    log.info("  Classes removed: 0 / N/A (N/A; stage not run)");
    log.info("  Methods removed: 0 / N/A (N/A; stage not run)");
    log.info("  Fields removed: 0 / N/A (N/A; stage not run)");
    log.info("  Cache: unavailable");
  }
}
