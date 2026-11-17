/* WHY: Classifies bytecode links so bounded closure omits only excluded method-body edges. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.scanner.AsmClassReferenceVisitor;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.objectweb.asm.ClassReader;

/** Extracts typed class edges from class-file metadata and selected method bodies. */
final class ClassReferenceEvidence {
  /** Bitmask for structural class-header/signature edges. */
  private static final int STRUCTURAL_BIT = 1 << ReferenceGraph.EdgeKind.STRUCTURAL.ordinal();

  /** Bitmask for method-body bytecode edges. */
  private static final int BODY_BIT = 1 << ReferenceGraph.EdgeKind.BODY.ordinal();

  /** Bitmask for debug-metadata edges. */
  private static final int DEBUG_BIT = 1 << ReferenceGraph.EdgeKind.DEBUG_METADATA.ordinal();

  /** Precomputed immutable EdgeKind sets indexed by ordinal bitmask. */
  private static final List<Set<ReferenceGraph.EdgeKind>> EDGE_SETS = computeEdgeSets();

  private ClassReferenceEvidence() {}

  // The default access modifier keeps this extractor package-private.
  // WHY: Only graph assembly needs this method.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static Result references(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<String, Set<ReferenceGraph.EdgeKind>> immutable =
        collectReferences(sourceClass, bytes, includeMethodBodies);
    try {
      return new Result(immutable, ClassFileAttributeInventory.unrecognizedAttributes(bytes));
    } catch (final java.io.IOException exception) {
      throw new IllegalArgumentException(
          "Could not inspect class-file attributes for class " + sourceClass, exception);
    }
  }

  // WHY: Visitor maps are local; ASM parser failures use unchecked exceptions.
  // The default access modifier keeps this helper package-private for JMH isolation.
  @SuppressWarnings({
    "PMD.UseConcurrentHashMap",
    "PMD.AvoidCatchingGenericException",
    "PMD.CommentDefaultAccessModifier"
  })
  static Map<String, Set<ReferenceGraph.EdgeKind>> collectReferences(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<String, Integer> masks = new HashMap<>();
    masks.put(sourceClass, STRUCTURAL_BIT);
    try {
      new ClassReader(bytes)
          .accept(
              new AsmClassReferenceVisitor(
                  sourceClass,
                  includeMethodBodies,
                  (target, kind) ->
                      masks.merge(target, edgeBit(kind), ClassReferenceEvidence::orMask)),
              0);
    } catch (final RuntimeException exception) {
      throw new IllegalArgumentException(
          "Could not classify references for class " + sourceClass, exception);
    }
    final Map<String, Set<ReferenceGraph.EdgeKind>> resolved = HashMap.newHashMap(masks.size());
    masks.forEach((target, mask) -> resolved.put(target, EDGE_SETS.get(mask)));
    return Collections.unmodifiableMap(resolved);
  }

  private static int orMask(final int left, final int right) {
    return left | right;
  }

  private static int edgeBit(final AsmClassReferenceVisitor.ReferenceKind kind) {
    return switch (kind) {
      case STRUCTURAL -> STRUCTURAL_BIT;
      case BODY -> BODY_BIT;
      case DEBUG_METADATA -> DEBUG_BIT;
    };
  }

  private static List<Set<ReferenceGraph.EdgeKind>> computeEdgeSets() {
    final ReferenceGraph.EdgeKind[] kinds = ReferenceGraph.EdgeKind.values();
    return IntStream.range(0, 1 << kinds.length)
        .mapToObj(
            mask -> {
              final Set<ReferenceGraph.EdgeKind> set =
                  EnumSet.noneOf(ReferenceGraph.EdgeKind.class);
              for (int bit = 0; bit < kinds.length; bit++) {
                if ((mask & (1 << bit)) != 0) {
                  set.add(kinds[bit]);
                }
              }
              return Set.copyOf(set);
            })
        .toList();
  }

  // The default access modifier keeps this result internal to the trimmer.
  // WHY: Graph construction consumes the immutable classification result.
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  record Result(
      Map<String, Set<ReferenceGraph.EdgeKind>> references, Set<String> unrecognizedAttributes) {}
}
