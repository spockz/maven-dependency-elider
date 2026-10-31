/* WHY: Keeps structured attribution review-only until exact mapping is proven. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.model.VulnerabilitySymbolMapping.ConfidenceLevel;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Structured CNA claims with resolved or unresolved class attribution for review. */
public record StructuredSourceClassEvidence(
    AdvisoryScope scope,
    AdvisoryProvenance provenance,
    String affectedProductIdentity,
    Set<String> programFiles,
    Set<String> programRoutines,
    Map<String, Set<String>> fileClassAttribution,
    Map<String, Set<String>> routineClassAttribution)
    implements AdvisoryEvidence {
  /** Validates keyed attribution; empty class sets are unresolved. */
  public StructuredSourceClassEvidence {
    Objects.requireNonNull(scope, "scope");
    Objects.requireNonNull(provenance, "provenance");
    if (provenance.origin() != EvidenceOrigin.CVE_LIST
        || provenance.sourceRecordSha256() == null
        || !provenance.sourceRecordId().equals(scope.cveId())) {
      throw new IllegalArgumentException(
          "Structured source evidence requires CVE record provenance");
    }
    if (affectedProductIdentity == null || affectedProductIdentity.isBlank()) {
      throw new IllegalArgumentException("affectedProductIdentity must not be blank");
    }
    programFiles = immutableNonBlankSet(programFiles, "programFiles");
    programRoutines = immutableNonBlankSet(programRoutines, "programRoutines");
    if (programFiles.isEmpty() && programRoutines.isEmpty()) {
      throw new IllegalArgumentException("Structured source evidence requires a file or routine");
    }
    fileClassAttribution = immutableAttribution(fileClassAttribution, "fileClassAttribution");
    routineClassAttribution =
        immutableAttribution(routineClassAttribution, "routineClassAttribution");
    if (!fileClassAttribution.keySet().equals(programFiles)
        || !routineClassAttribution.keySet().equals(programRoutines)) {
      throw new IllegalArgumentException(
          "Every structured source entry requires exact attribution");
    }
  }

  /** Returns candidate classes associated with the structured source entries. */
  public Set<String> vulnerableClasses() {
    final Set<String> classes = new TreeSet<>();
    fileClassAttribution.values().forEach(classes::addAll);
    routineClassAttribution.values().forEach(classes::addAll);
    return Set.copyOf(classes);
  }

  @Override
  public ConfidenceLevel confidenceLabel() {
    return ConfidenceLevel.MEDIUM;
  }

  private static Set<String> immutableNonBlankSet(final Set<String> values, final String field) {
    Objects.requireNonNull(values, field);
    final Set<String> copy = new TreeSet<>();
    for (final String value : values) {
      if (value == null || value.isBlank()) {
        throw new IllegalArgumentException(field + " must contain non-blank strings");
      }
      copy.add(value);
    }
    return Set.copyOf(copy);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private static Map<String, Set<String>> immutableAttribution(
      final Map<String, Set<String>> attribution, final String field) {
    Objects.requireNonNull(attribution, field);
    final Map<String, Set<String>> copy = new TreeMap<>();
    for (final Map.Entry<String, Set<String>> entry : attribution.entrySet()) {
      if (entry.getKey() == null || entry.getKey().isBlank()) {
        throw new IllegalArgumentException(field + " contains a blank source key");
      }
      final Set<String> classes = immutableNonBlankSet(entry.getValue(), field + " classes");
      if (classes.stream().anyMatch(value -> !isTopLevelClassName(value))) {
        throw new IllegalArgumentException(field + " must contain top-level class names");
      }
      copy.put(entry.getKey(), classes);
    }
    return Map.copyOf(copy);
  }

  private static boolean isTopLevelClassName(final String value) {
    return value.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")
        && value.indexOf('$') < 0;
  }
}
