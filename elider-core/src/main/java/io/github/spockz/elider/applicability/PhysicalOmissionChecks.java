/* WHY: Shares exact archive and digest checks between POM and structured proof paths. */

package io.github.spockz.elider.applicability;

import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

/** Physical archive checks shared by the model's proof admission paths. */
final class PhysicalOmissionChecks {
  private PhysicalOmissionChecks() {}

  /* default */ static Set<String> verifySymbols(
      final Set<String> vulnerableClasses,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    final Set<String> absent = new TreeSet<>();
    for (final String mapped : vulnerableClasses) {
      final String binaryName = mapped.replace('.', '/');
      if (originalClasses.contains(binaryName)) {
        absent.addAll(verifyPrunedSymbols(binaryName, originalClasses, trimmedClasses));
      }
      verifyNoSurvivingNested(binaryName, trimmedClasses);
    }
    if (absent.isEmpty()) {
      throw new IllegalArgumentException(
          "Mapped class is absent from original archive: "
              + String.join(", ", new TreeSet<>(vulnerableClasses)));
    }
    return absent;
  }

  private static Set<String> verifyPrunedSymbols(
      final String binaryName,
      final Set<String> originalClasses,
      final Set<String> trimmedClasses) {
    final Set<String> absent = new TreeSet<>();
    for (final String symbol : nestedSymbols(binaryName, originalClasses)) {
      if (trimmedClasses.contains(symbol)) {
        throw new IllegalArgumentException(
            "Vulnerable class survives trimmed archive: " + symbol.replace('/', '.'));
      }
      absent.add(symbol.replace('/', '.'));
    }
    return absent;
  }

  private static void verifyNoSurvivingNested(
      final String binaryName, final Set<String> trimmedClasses) {
    final String nestedPrefix = binaryName + "$";
    for (final String trimmed : trimmedClasses) {
      if (trimmed.startsWith(nestedPrefix)) {
        throw new IllegalArgumentException(
            "Vulnerable nested class survives trimmed archive: " + trimmed.replace('/', '.'));
      }
    }
  }

  /* default */ static Set<String> nestedSymbols(
      final String binaryName, final Set<String> originalClasses) {
    final Set<String> symbols = new HashSet<>();
    symbols.add(binaryName);
    final String nestedPrefix = binaryName + "$";
    for (final String original : originalClasses) {
      if (original.startsWith(nestedPrefix)) {
        symbols.add(original);
      }
    }
    return symbols;
  }
}
