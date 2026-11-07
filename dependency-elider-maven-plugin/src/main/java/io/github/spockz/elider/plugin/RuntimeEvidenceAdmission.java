/* WHY: Validates runtime inputs before planning or publication. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.trace.CompositeTraceEvidence;
import io.github.spockz.elider.trace.TraceEvidenceKind;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/** Admits evidence against application and dependency classes. */
final class RuntimeEvidenceAdmission {
  private RuntimeEvidenceAdmission() {}

  /* default */ static RuntimeEvidencePolicy admit(
      final CompositeTraceEvidence evidence,
      final boolean closedWorld,
      final Set<String> relevantClasses,
      final Set<String> explicitRoots,
      final Set<String> activeDynamicRoots)
      throws IOException {
    if (evidence.inputs().isEmpty()) {
      throw new IOException("At least one explicit runtime evidence input is required");
    }
    final Set<String> observed = normalize(evidence.observations().loadedClassesDotFormat());
    final Set<String> normalizedRelevant = normalize(relevantClasses);
    final Set<String> allowed = new TreeSet<>(observed);
    allowed.addAll(normalize(explicitRoots));
    allowed.addAll(normalize(activeDynamicRoots));
    final Set<TraceEvidenceKind> kinds = new TreeSet<>();
    for (final CompositeTraceEvidence.Input input : evidence.inputs()) {
      validateInput(input, closedWorld, normalizedRelevant);
      kinds.add(input.kind());
    }
    return new RuntimeEvidencePolicy(closedWorld, observed, allowed, kinds);
  }

  private static void validateInput(
      final CompositeTraceEvidence.Input input,
      final boolean closedWorld,
      final Set<String> normalizedRelevant)
      throws IOException {
    validateNotEmpty(input);
    validateKind(input);
    validateRelevant(input, closedWorld, normalizedRelevant);
  }

  private static void validateNotEmpty(final CompositeTraceEvidence.Input input)
      throws IOException {
    if (input.observations().size() == 0) {
      throw new IOException("Runtime evidence input is empty: " + input.path());
    }
  }

  private static void validateKind(final CompositeTraceEvidence.Input input) throws IOException {
    if (input.kind() == TraceEvidenceKind.UNCLASSIFIED) {
      throw new IOException("Unsupported runtime evidence kind: " + input.path());
    }
  }

  private static void validateRelevant(
      final CompositeTraceEvidence.Input input,
      final boolean closedWorld,
      final Set<String> normalizedRelevant)
      throws IOException {
    if (!closedWorld) {
      return;
    }
    if (input.kind() == TraceEvidenceKind.GRAAL_CONFIGURATION) {
      throw new IOException("Graal configuration is not runtime class evidence: " + input.path());
    }
    if (input.observations().loadedClassesDotFormat().stream()
        .map(TraceData::normalizeToDot)
        .noneMatch(normalizedRelevant::contains)) {
      throw new IOException("Closed-world evidence input is irrelevant: " + input.path());
    }
  }

  private static Set<String> normalize(final Set<String> classes) {
    final Set<String> normalized = new HashSet<>();
    for (final String className : classes) {
      if (className != null && !className.isBlank()) {
        normalized.add(TraceData.normalizeToDot(className.trim()));
      }
    }
    return normalized;
  }
}
