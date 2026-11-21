// WHY: Finds exact symbolic invocation evidence in the effective bytecode available to Elider.

package io.github.spockz.elider.advisory;

import io.github.spockz.elider.advisory.ForbiddenCodeInventory.Evidence;
import io.github.spockz.elider.advisory.ForbiddenCodeInventory.Inner;
import io.github.spockz.elider.model.MultiReleaseEntryPath;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Matches symbolic JVM invocations using caller bytecode. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
public final class ForbiddenRuntimeCalls {
  private static final String CONSTRUCTOR = "<init>";
  private final Map<String, Map<String, List<ForbiddenSymbol>>> targets;

  private record Match(ForbiddenSymbol symbol, Evidence evidence) {}

  private record EntryMatches(int tier, Set<Match> matches) {}

  private record Target(String owner, List<Type> parameters) {}

  private ForbiddenRuntimeCalls(final Map<String, Map<String, List<ForbiddenSymbol>>> targets) {
    this.targets = targets;
  }

  /** Indexes exact method rules by owner and name. */
  public static ForbiddenRuntimeCalls index(final Collection<ForbiddenSymbol> symbols) {
    final Map<String, Map<String, List<ForbiddenSymbol>>> targets = new HashMap<>();
    for (final ForbiddenSymbol symbol : symbols) {
      if (symbol.method() != null) {
        targets
            .computeIfAbsent(symbol.owner(), ignored -> new HashMap<>())
            .computeIfAbsent(symbol.method(), ignored -> new ArrayList<>())
            .add(symbol);
      }
    }
    return new ForbiddenRuntimeCalls(targets);
  }

  /** Requires one binary owner and argument signature. */
  public static boolean unambiguous(final Collection<Evidence> evidence) {
    return evidence.stream()
            .map(hit -> new Target(hit.owner(), List.of(Type.getArgumentTypes(hit.descriptor()))))
            .distinct()
            .limit(2)
            .count()
        == 1;
  }

  /** Returns candidate matches in the effective target-release view of one provider. */
  public Map<ForbiddenSymbol, List<Evidence>> scan(
      final Path provider,
      final Set<String> removedClasses,
      final Map<String, String> projectedEntries,
      final int targetRelease)
      throws IOException {
    if (targets.isEmpty()) {
      return Map.of();
    }
    final Map<String, EntryMatches> entries = new LinkedHashMap<>();
    final EntryMatches base = new EntryMatches(0, new LinkedHashSet<>());
    ForbiddenCodeInventory.visitRetained(
        provider,
        removedClasses,
        projectedEntries,
        (reader, entry, tier, multiRelease) -> {
          if (multiRelease && tier <= targetRelease) {
            scanVersionedClass(reader, entry, tier, entries);
          } else if (tier == 0) {
            readCalls(reader, entry, base);
          }
        });
    final Map<ForbiddenSymbol, List<Evidence>> result = new HashMap<>();
    base.matches().forEach(match -> addMatch(result, match));
    entries.values().forEach(entry -> entry.matches().forEach(match -> addMatch(result, match)));
    result.replaceAll((key, hits) -> List.copyOf(hits));
    return Map.copyOf(result);
  }

  private static void addMatch(
      final Map<ForbiddenSymbol, List<Evidence>> result, final Match match) {
    result.computeIfAbsent(match.symbol(), ignored -> new ArrayList<>()).add(match.evidence());
  }

  private void scanVersionedClass(
      final ClassReader reader,
      final String entry,
      final int tier,
      final Map<String, EntryMatches> entries)
      throws IOException {
    final String logical =
        tier == 0 ? entry : MultiReleaseEntryPath.parse(entry, false).logicalName();
    final EntryMatches selected =
        entries.compute(
            logical,
            (key, current) ->
                current == null || current.tier() < tier
                    ? new EntryMatches(tier, new LinkedHashSet<>())
                    : current);
    if (selected.tier() == tier) {
      readCalls(reader, entry, selected);
    }
  }

  private void readCalls(final ClassReader reader, final String entry, final EntryMatches matches) {
    reader.accept(
        new CallVisitor(entry, matches), ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
  }

  private final class CallVisitor extends ClassVisitor {
    private final Map<String, Optional<Inner>> inners = new HashMap<>();
    private final String entry;
    private final EntryMatches selected;
    private final MethodVisitor methodVisitor;

    private CallVisitor(final String entry, final EntryMatches selected) {
      super(Opcodes.ASM9);
      this.entry = entry;
      this.selected = selected;
      methodVisitor =
          new MethodVisitor(Opcodes.ASM9) {
            @Override
            public void visitMethodInsn(
                final int opcode,
                final String owner,
                final String name,
                final String descriptor,
                final boolean isInterface) {
              final String binary = owner.replace('/', '.');
              final String source = sourceName(binary);
              collect(binary, name, descriptor, binary);
              if (source != null && !source.equals(binary)) {
                collect(source, name, descriptor, binary);
              }
            }
          };
    }

    @Override
    public void visitInnerClass(
        final String name, final String outer, final String simple, final int access) {
      if (outer != null && simple != null) {
        inners.merge(
            name.replace('/', '.'),
            Optional.of(new Inner(outer.replace('/', '.'), simple)),
            (previous, observed) -> previous.equals(observed) ? previous : Optional.empty());
      }
    }

    @Override
    public MethodVisitor visitMethod(
        final int access,
        final String name,
        final String descriptor,
        final String signature,
        final String[] exceptions) {
      return methodVisitor;
    }

    private void collect(
        final String spelling, final String name, final String descriptor, final String binary) {
      final Map<String, List<ForbiddenSymbol>> methods = targets.get(spelling);
      if (methods == null) {
        return;
      }
      if (CONSTRUCTOR.equals(name)) {
        final String simple = spelling.substring(spelling.lastIndexOf('.') + 1);
        collectMatching(methods.get(simple), descriptor, binary);
        inners
            .getOrDefault(binary, Optional.empty())
            .map(Inner::simple)
            .filter(member -> !member.equals(simple))
            .ifPresent(member -> collectMatching(methods.get(member), descriptor, binary));
      } else {
        collectMatching(methods.get(name), descriptor, binary);
      }
    }

    private void collectMatching(
        final List<ForbiddenSymbol> rules, final String descriptor, final String binary) {
      if (rules == null) {
        return;
      }
      final Type[] arguments = Type.getArgumentTypes(descriptor);
      for (final ForbiddenSymbol rule : rules) {
        if (matchesParameters(arguments, rule.parameters())) {
          selected
              .matches()
              .add(new Match(rule, new Evidence(binary, descriptor, entry, selected.tier())));
        }
      }
    }

    private boolean matchesParameters(final Type[] arguments, final List<String> parameters) {
      if (arguments.length != parameters.size()) {
        return false;
      }
      for (int i = 0; i < arguments.length; i++) {
        final Type argument = arguments[i];
        final String expected = parameters.get(i);
        if (!argument.getClassName().equals(expected) && !expected.equals(sourceType(argument))) {
          return false;
        }
      }
      return true;
    }

    private String sourceType(final Type argument) {
      final Type element = argument.getSort() == Type.ARRAY ? argument.getElementType() : argument;
      if (element.getSort() != Type.OBJECT) {
        return null;
      }
      final String source = sourceName(element.getClassName());
      if (argument.getSort() == Type.ARRAY && source != null) {
        return source + "[]".repeat(argument.getDimensions());
      }
      return source;
    }

    private String sourceName(final String binary) {
      return inners.containsKey(binary) ? sourceName(binary, new HashSet<>()) : binary;
    }

    private String sourceName(final String binary, final Set<String> seen) {
      final Optional<Inner> member = inners.get(binary);
      if (member == null) {
        return binary;
      }
      if (member.isEmpty() || !seen.add(binary)) {
        return null;
      }
      final Inner inner = member.orElseThrow();
      final String outer = sourceName(inner.outer(), seen);
      return outer == null ? null : outer + "." + inner.simple();
    }
  }
}
