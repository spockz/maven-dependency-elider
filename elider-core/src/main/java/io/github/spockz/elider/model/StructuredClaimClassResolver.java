/* WHY: Maps only freshly reproduced CNA claims to their exact emitted class families. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.correspondence.SourceReproductionResult;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Derives proof class families from current file and unique routine claims. */
final class StructuredClaimClassResolver {
  /** One exact entry must own each current file or routine claim. */
  private static final int UNIQUE_MATCH_COUNT = 1;

  private StructuredClaimClassResolver() {}

  /* default */ static Result derive(
      final CveAffectedEntryContext entry, final SourceReproductionResult.Completed completed)
      throws IOException {
    final Set<String> selectedEntries = new HashSet<>();
    final List<StructuredProofProvenance.ClaimAttribution> attributions = new ArrayList<>();
    for (final String claim : entry.programFiles().stream().sorted().toList()) {
      final String sourceEntry = completed.mappedClaims().get(claim);
      if (sourceEntry == null) {
        throw new IOException("A current CNA source-file claim has no exact archive match");
      }
      final List<SourceReproductionResult.SourceUnit> units =
          completed.sourceUnits().stream()
              .filter(unit -> unit.sourceEntry().equals(sourceEntry))
              .toList();
      if (units.size() != UNIQUE_MATCH_COUNT) {
        throw new IOException("A matched source claim has no unique reproduced source unit");
      }
      final SourceReproductionResult.SourceUnit unit = units.getFirst();
      final List<SourceReproductionResult.ClassEntry> emittedClasses =
          orderedClasses(unit.emittedClasses());
      selectedEntries.addAll(classNames(emittedClasses));
      attributions.add(
          new StructuredProofProvenance.ClaimAttribution(
              StructuredProofProvenance.ClaimType.FILE, claim, sourceEntry, null, emittedClasses));
    }
    for (final String routine : entry.programRoutines().stream().sorted().toList()) {
      attributions.add(addRoutineOwnerFamily(routine, completed, selectedEntries));
    }
    if (selectedEntries.isEmpty()) {
      throw new IOException("Current CNA claims identify no reproduced class family");
    }
    return new Result(selectedEntries, attributions);
  }

  private static StructuredProofProvenance.ClaimAttribution addRoutineOwnerFamily(
      final String routine,
      final SourceReproductionResult.Completed completed,
      final Set<String> selectedEntries)
      throws IOException {
    final List<SourceReproductionResult.RoutineDeclaration> declarations =
        completed.sourceUnits().stream()
            .flatMap(unit -> unit.routineDeclarations().stream())
            .filter(declaration -> declaration.name().equals(routine))
            .toList();
    if (declarations.size() != UNIQUE_MATCH_COUNT) {
      throw new IOException("A current CNA routine claim has no unique reproduced owner");
    }
    final String owner = declarations.getFirst().ownerBinaryName();
    final String ownerPath = owner.replace('.', '/') + ".class";
    final List<SourceReproductionResult.SourceUnit> ownerUnits =
        completed.sourceUnits().stream().filter(unit -> emitsOwner(unit, ownerPath)).toList();
    if (ownerUnits.size() != UNIQUE_MATCH_COUNT) {
      throw new IOException("A routine owner is not emitted by one reproduced source unit");
    }
    final SourceReproductionResult.SourceUnit ownerUnit = ownerUnits.getFirst();
    final String nestedPrefix = owner.replace('.', '/') + "$";
    final List<SourceReproductionResult.ClassEntry> familyEntries =
        orderedClasses(
            ownerUnit.emittedClasses().stream()
                .filter(entry -> isOwnerFamilyEntry(entry, ownerPath, nestedPrefix))
                .toList());
    final Set<String> family = classNames(familyEntries);
    if (!family.contains(owner)) {
      throw new IOException("A routine owner is absent from the reproduced class inventory");
    }
    selectedEntries.addAll(family);
    return new StructuredProofProvenance.ClaimAttribution(
        StructuredProofProvenance.ClaimType.ROUTINE,
        routine,
        ownerUnit.sourceEntry(),
        owner,
        familyEntries);
  }

  private static boolean emitsOwner(
      final SourceReproductionResult.SourceUnit unit, final String ownerPath) {
    return unit.emittedClasses().stream().anyMatch(entry -> ownerPath.equals(entry.path()));
  }

  private static boolean isOwnerFamilyEntry(
      final SourceReproductionResult.ClassEntry entry,
      final String ownerPath,
      final String nestedPrefix) {
    return entry.path().equals(ownerPath) || entry.path().startsWith(nestedPrefix);
  }

  private static List<SourceReproductionResult.ClassEntry> orderedClasses(
      final List<SourceReproductionResult.ClassEntry> classEntries) {
    return classEntries.stream()
        .sorted(java.util.Comparator.comparing(SourceReproductionResult.ClassEntry::path))
        .toList();
  }

  private static Set<String> classNames(
      final List<SourceReproductionResult.ClassEntry> classEntries) throws IOException {
    final Set<String> names = new HashSet<>();
    for (final SourceReproductionResult.ClassEntry entry : classEntries) {
      names.add(className(entry.path()));
    }
    return names;
  }

  private static String className(final String path) throws IOException {
    if (!path.endsWith(".class") || path.startsWith("/") || path.contains("..")) {
      throw new IOException("Reproduced class inventory contains an invalid physical entry");
    }
    return path.substring(0, path.length() - ".class".length()).replace('/', '.');
  }

  /** Immutable result of mapping current source claims to reproduced outputs. */
  /* default */ record Result(
      Set<String> classNames, List<StructuredProofProvenance.ClaimAttribution> attributions) {
    /** Freezes the derived proof inputs. */
    Result {
      classNames = Set.copyOf(classNames);
      attributions = List.copyOf(attributions);
    }
  }
}
