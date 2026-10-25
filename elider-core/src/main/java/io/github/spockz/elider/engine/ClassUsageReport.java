/* WHY: Joins dependency class inventory with runtime and application-bytecode evidence for
 * diagnostics while keeping report classification separate from artifact pruning policy. */

package io.github.spockz.elider.engine;

import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.OriginEvidence;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.BytecodeReferenceScan;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Deterministic class-level diagnostic classifications over dependency inventory. */
@SuppressWarnings({
  "PMD.LongVariable",
  "PMD.LooseCoupling",
  "PMD.CommentSize",
  "PMD.ConfusingTernary"
})
public record ClassUsageReport(List<ClassUsage> classes) {
  /** Stable owner ordering by Maven coordinate and artifact path. */
  private static final Comparator<ArtifactFileRef> ARTIFACT_ORDER =
      Comparator.comparing(ArtifactFileRef::coordinate)
          .thenComparing(ref -> ref.filePath().toString())
          .thenComparingLong(ArtifactFileRef::lastModified)
          .thenComparingLong(ArtifactFileRef::fileSize);

  /** Classification categories retain the distinct static/runtime evidence states. */
  public enum Category {
    APPLICATION_REFERENCED_AND_RUNTIME_OBSERVED,
    APPLICATION_REFERENCED_NOT_RUNTIME_OBSERVED,
    RUNTIME_OBSERVED_WITHOUT_APPLICATION_REFERENCE,
    NEITHER_REFERENCED_NOR_OBSERVED,
    RUNTIME_OBSERVED_WITH_UNKNOWN_STATIC_EVIDENCE,
    UNKNOWN_STATIC_EVIDENCE
  }

  /** Evidence for one indexed dependency class, including every indexed owner. */
  public record ClassUsage(
      String className,
      Category category,
      boolean applicationBytecodeReferenced,
      boolean runtimeObserved,
      boolean staticEvidenceAvailable,
      Set<ArtifactFileRef> owners,
      Optional<OriginEvidence> originEvidence) {
    /** Copies owner evidence into a stable immutable order. */
    public ClassUsage {
      Objects.requireNonNull(className, "className");
      Objects.requireNonNull(category, "category");
      Objects.requireNonNull(owners, "owners");
      Objects.requireNonNull(originEvidence, "originEvidence");
      final TreeSet<ArtifactFileRef> sortedOwners = new TreeSet<>(ARTIFACT_ORDER);
      sortedOwners.addAll(owners);
      owners = java.util.Collections.unmodifiableSet(sortedOwners);
    }
  }

  /** Sorts report rows by class name and snapshots them. */
  public ClassUsageReport {
    Objects.requireNonNull(classes, "classes");
    final List<ClassUsage> sorted = new ArrayList<>(classes);
    sorted.sort(Comparator.comparing(ClassUsage::className));
    classes = List.copyOf(sorted);
  }

  /** Returns both application-reference states in stable class-name order. */
  public List<ClassUsage> applicationBytecodeReferenced() {
    return classes.stream().filter(ClassUsage::applicationBytecodeReferenced).toList();
  }

  /** Returns observed classes lacking application references when the scan completed. */
  public List<ClassUsage> runtimeObservedWithoutApplicationReference() {
    return classes.stream()
        .filter(
            usage -> usage.category() == Category.RUNTIME_OBSERVED_WITHOUT_APPLICATION_REFERENCE)
        .toList();
  }

  /** Returns neither-referenced-nor-observed classes when the scan completed. */
  public List<ClassUsage> neitherReferencedNorObserved() {
    return classes.stream()
        .filter(usage -> usage.category() == Category.NEITHER_REFERENCED_NOR_OBSERVED)
        .toList();
  }

  /** Returns runtime observations whose static-reference evidence is unknown. */
  public List<ClassUsage> runtimeObservedWithUnknownStaticEvidence() {
    return classes.stream()
        .filter(usage -> usage.category() == Category.RUNTIME_OBSERVED_WITH_UNKNOWN_STATIC_EVIDENCE)
        .toList();
  }

  /**
   * Joins classes from the dependency inventory with completed static scan and runtime evidence.
   */
  public static ClassUsageReport classify(
      final ArtifactClassIndex inventory,
      final TraceData runtimeTrace,
      final Optional<BytecodeReferenceScan> bytecodeScan) {
    Objects.requireNonNull(inventory, "inventory");
    Objects.requireNonNull(runtimeTrace, "runtimeTrace");
    Objects.requireNonNull(bytecodeScan, "bytecodeScan");
    final boolean staticAvailable =
        bytecodeScan.filter(BytecodeReferenceScan::complete).isPresent();
    final Set<String> references =
        bytecodeScan
            .filter(BytecodeReferenceScan::complete)
            .map(BytecodeReferenceScan::referencedClasses)
            .orElseGet(Set::of);
    final TreeMap<String, Set<ArtifactFileRef>> ownersByClass = new TreeMap<>();
    inventory
        .classesByArtifact()
        .forEach(
            (artifact, names) ->
                names.forEach(
                    name ->
                        ownersByClass
                            .computeIfAbsent(name, key -> new TreeSet<>(ARTIFACT_ORDER))
                            .add(artifact)));

    final List<ClassUsage> rows = new ArrayList<>(ownersByClass.size());
    ownersByClass.forEach(
        (name, owners) -> {
          final boolean referenced = references.contains(name);
          final boolean observed = runtimeTrace.contains(name);
          final Category category;
          if (!staticAvailable && observed) {
            category = Category.RUNTIME_OBSERVED_WITH_UNKNOWN_STATIC_EVIDENCE;
          } else if (!staticAvailable) {
            category = Category.UNKNOWN_STATIC_EVIDENCE;
          } else if (referenced && observed) {
            category = Category.APPLICATION_REFERENCED_AND_RUNTIME_OBSERVED;
          } else if (referenced) {
            category = Category.APPLICATION_REFERENCED_NOT_RUNTIME_OBSERVED;
          } else if (observed) {
            category = Category.RUNTIME_OBSERVED_WITHOUT_APPLICATION_REFERENCE;
          } else {
            category = Category.NEITHER_REFERENCED_NOR_OBSERVED;
          }
          rows.add(
              new ClassUsage(
                  name,
                  category,
                  referenced,
                  observed,
                  staticAvailable,
                  owners,
                  observed ? Optional.of(runtimeTrace.originsFor(name)) : Optional.empty()));
        });
    return new ClassUsageReport(rows);
  }
}
