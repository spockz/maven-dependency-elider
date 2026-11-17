/* WHY: Preserves the pre-optimization EnumSet edge collector verbatim for JMH comparison. */

package io.github.spockz.elider.trimmer;

import io.github.spockz.elider.scanner.AsmClassReferenceVisitor;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.ClassReader;

/** Verbatim pre-optimization EnumSet edge collector for ClassReferenceEvidence. */
final class BaselineClassReferenceEvidence {
  private BaselineClassReferenceEvidence() {}

  @SuppressWarnings({"PMD.UseConcurrentHashMap", "PMD.CommentDefaultAccessModifier"})
  static Map<String, Set<ReferenceGraph.EdgeKind>> collectReferences(
      final String sourceClass, final byte[] bytes, final boolean includeMethodBodies) {
    final Map<String, Set<ReferenceGraph.EdgeKind>> references = new LinkedHashMap<>();
    references
        .computeIfAbsent(sourceClass, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
        .add(ReferenceGraph.EdgeKind.STRUCTURAL);
    new ClassReader(bytes)
        .accept(
            new AsmClassReferenceVisitor(
                sourceClass,
                includeMethodBodies,
                (target, kind) ->
                    references
                        .computeIfAbsent(
                            target, unused -> EnumSet.noneOf(ReferenceGraph.EdgeKind.class))
                        .add(toEdgeKind(kind))),
            0);
    final Map<String, Set<ReferenceGraph.EdgeKind>> immutable = new HashMap<>();
    references.forEach((target, kinds) -> immutable.put(target, Set.copyOf(kinds)));
    return Map.copyOf(immutable);
  }

  private static ReferenceGraph.EdgeKind toEdgeKind(
      final AsmClassReferenceVisitor.ReferenceKind kind) {
    return switch (kind) {
      case STRUCTURAL -> ReferenceGraph.EdgeKind.STRUCTURAL;
      case BODY -> ReferenceGraph.EdgeKind.BODY;
      case DEBUG_METADATA -> ReferenceGraph.EdgeKind.DEBUG_METADATA;
    };
  }
}
