// WHY: Displays saved test-view results without inferring production omissions or mitigation.

package io.github.spockz.elider.plugin;

import java.util.ArrayList;
import java.util.List;

/** Produces deterministic console lines from a validated test-view observation. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TestClassWithoutTestCases"})
final class TestViewReportRenderer {
  private TestViewReportRenderer() {}

  static List<String> render(final TestViewReportSnapshot snapshot) {
    if (snapshot.status() == TestViewReportSnapshot.Status.UNAVAILABLE) {
      return List.of("Test view: unavailable: " + snapshot.reason());
    }
    final List<String> lines = new ArrayList<>();
    lines.add("Test view: prepared");
    lines.add("Test compilation output: " + snapshot.testOutputDirectory());
    lines.add("Original mediated test inputs: " + snapshot.inputArtifacts().size());
    for (final TestViewReportSnapshot.InputArtifact input : snapshot.inputArtifacts()) {
      if (!input.originalJar().equals(input.effectiveJar())) {
        lines.add(
            "  - "
                + input.identity()
                + ": "
                + input.originalJar()
                + " -> "
                + (input.effectiveJar() == null
                    ? "absent from effective view"
                    : input.effectiveJar()));
      }
    }
    lines.add(
        "Test-only added classes: "
            + snapshot.addedClassCount()
            + " in "
            + snapshot.additions().size()
            + " artifacts");
    for (final TestViewReportSnapshot.Addition addition : snapshot.additions()) {
      lines.add("  - " + addition.identity() + ": " + addition.classes());
    }
    lines.add(
        "Test-only additions JAR: "
            + (snapshot.additionsJar() == null ? "none" : snapshot.additionsJar()));
    lines.add("Conservative test-only fallback: " + snapshot.conservativeFallbackUsed());
    return List.copyOf(lines);
  }
}
