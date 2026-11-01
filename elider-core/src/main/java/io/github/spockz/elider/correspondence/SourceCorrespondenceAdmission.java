// WHY: Enforces unique routine owners and complete byte-equal physical class inventories.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Validates claim resolution and the disjoint source-unit output union. */
final class SourceCorrespondenceAdmission {
  /** A routine name may identify only one declaration across the complete archive. */
  private static final int UNIQUE_OWNER_COUNT = 1;

  private SourceCorrespondenceAdmission() {}

  /* default */ static void requireUniqueRoutineOwners(
      final List<SourceReproductionResult.SourceUnit> units, final List<String> claims)
      throws IOException {
    if (claims == null || claims.isEmpty()) {
      return;
    }
    for (final String claim : claims) {
      requireRoutineName(claim);
      final List<SourceReproductionResult.RoutineDeclaration> matches =
          units.stream()
              .flatMap(unit -> unit.routineDeclarations().stream())
              .filter(declaration -> declaration.name().equals(claim))
              .toList();
      if (matches.size() != UNIQUE_OWNER_COUNT) {
        throw routineMismatch(claim, matches.isEmpty());
      }
    }
  }

  /* default */
  @SuppressWarnings("PMD.UseConcurrentHashMap") // Inventory maps are local to this validation.
  static void requireInventoryMatch(
      final List<SourceReproductionResult.ClassEntry> original,
      final List<SourceReproductionResult.SourceUnit> units)
      throws IOException {
    final Map<String, String> expected = new HashMap<>();
    original.forEach(entry -> expected.put(entry.path(), entry.sha256()));
    final Map<String, String> reproduced = reproducedInventory(units);
    if (!expected.equals(reproduced)) {
      throw inventoryMismatch(expected, reproduced);
    }
  }

  private static void requireRoutineName(final String claim) throws IOException {
    if (claim == null || !claim.matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
      throw new IOException("Unsupported structured routine name: " + claim);
    }
  }

  private static IOException routineMismatch(final String claim, final boolean absent) {
    if (absent) {
      return new IOException(
          "Structured routine name is absent from the exact sources archive: " + claim);
    }
    return new IOException(
        "Structured routine name has multiple possible owners or overloads: " + claim);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // Reproduction maps are local to this validation.
  private static Map<String, String> reproducedInventory(
      final List<SourceReproductionResult.SourceUnit> units) throws IOException {
    final Map<String, String> reproduced = new HashMap<>();
    for (final SourceReproductionResult.SourceUnit unit : units) {
      for (final SourceReproductionResult.ClassEntry entry : unit.emittedClasses()) {
        if (reproduced.putIfAbsent(entry.path(), entry.sha256()) != null) {
          throw new IOException("Duplicate reproduced class path: " + entry.path());
        }
      }
    }
    return reproduced;
  }

  private static IOException inventoryMismatch(
      final Map<String, String> expected, final Map<String, String> reproduced) {
    final Set<String> missing = new HashSet<>(expected.keySet());
    missing.removeAll(reproduced.keySet());
    final Set<String> extra = new HashSet<>(reproduced.keySet());
    extra.removeAll(expected.keySet());
    final Set<String> changed = new HashSet<>(expected.keySet());
    changed.retainAll(reproduced.keySet());
    changed.removeIf(path -> expected.get(path).equals(reproduced.get(path)));
    return new IOException(
        "Reproduced class inventory differs from original JAR; missing="
            + missing.size()
            + ", extra="
            + extra.size()
            + ", byte-different="
            + changed.size());
  }
}
