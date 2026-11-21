// WHY: Inspects every physical class entry once to assess explicit forbidden code policies.

package io.github.spockz.elider.advisory;

import io.github.spockz.elider.model.MultiReleaseEntryPath;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/** Physical declarations in a selected provider. */
@SuppressWarnings({
  "PMD.CouplingBetweenObjects",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.CognitiveComplexity",
  "PMD.NPathComplexity",
  "PMD.TooManyMethods",
  "PMD.ExcessiveParameterList",
  "PMD.UseConcurrentHashMap",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.AvoidLiteralsInIfCondition"
})
public final class ForbiddenCodeInventory {
  /** Outcome of a physical observation. */
  public enum Status {
    PASS,
    VIOLATION,
    UNKNOWN
  }

  /** Bytecode evidence in a specific provider entry and release tier. */
  public record Evidence(String owner, String descriptor, String entry, int tier) {}

  /** Outcome and supporting entries. */
  public record Result(Status status, List<Evidence> evidence, String reason, boolean complete) {
    /** Preserve an immutable evidence list. */
    public Result {
      evidence = List.copyOf(evidence);
    }

    private Result(final Status status, final List<Evidence> evidence, final String reason) {
      this(status, evidence, reason, status != Status.UNKNOWN);
    }
  }

  private record Method(String name, String descriptor, int access) {}

  private record ClassInfo(
      String name,
      String parent,
      List<String> interfaces,
      List<Method> methods,
      int access,
      String entry,
      int tier) {}

  /* default */ record Inner(String outer, String simple) {}

  private ForbiddenCodeInventory() {}

  /** Inspect the retained entries of a provider. */
  public static Map<ForbiddenSymbol, Result> scan(
      final Path provider,
      final Collection<ForbiddenSymbol> symbols,
      final Set<String> removedClasses)
      throws IOException {
    return scan(provider, symbols, removedClasses, null);
  }

  /** Inspect a projected source-to-output entry mapping; null retains all entries. */
  public static Map<ForbiddenSymbol, Result> scan(
      final Path provider,
      final Collection<ForbiddenSymbol> symbols,
      final Set<String> removedClasses,
      final Map<String, String> projectedEntries)
      throws IOException {
    if (symbols.isEmpty()) {
      return Map.of();
    }
    final Map<String, List<ClassInfo>> classes = new HashMap<>();
    final Map<String, Inner> inners = new HashMap<>();
    final boolean inspectMethods = symbols.stream().anyMatch(symbol -> symbol.method() != null);
    visitRetained(
        provider,
        removedClasses,
        projectedEntries,
        (reader, entry, tier, multiRelease) ->
            readDeclarations(reader, entry, tier, classes, inners, inspectMethods));
    final Map<String, Set<String>> names = new HashMap<>();
    for (final String binary : classes.keySet()) {
      names
          .computeIfAbsent(sourceName(binary, inners, new HashSet<>()), k -> new HashSet<>())
          .add(binary);
      names.computeIfAbsent(binary, k -> new HashSet<>()).add(binary);
    }
    final Map<ForbiddenSymbol, Result> results = new LinkedHashMap<>();
    final Set<Integer> tiers = new java.util.TreeSet<>();
    if (inspectMethods) {
      classes.values().forEach(variants -> variants.forEach(variant -> tiers.add(variant.tier())));
    }
    for (final ForbiddenSymbol symbol : symbols) {
      results.put(symbol, assess(symbol, classes, names, inners, tiers));
    }
    return Map.copyOf(results);
  }

  @FunctionalInterface
  @SuppressWarnings({"PMD.CommentRequired", "PMD.CommentDefaultAccessModifier"})
  interface ClassEntryVisitor {
    void visit(ClassReader reader, String entry, int tier, boolean multiRelease) throws IOException;
  }

  /* default */ static void visitRetained(
      final Path provider,
      final Set<String> removedClasses,
      final Map<String, String> projectedEntries,
      final ClassEntryVisitor visitor)
      throws IOException {
    final ClassSelection selection = new ClassSelection(projectedEntries, removedClasses, visitor);
    if (Files.isDirectory(provider)) {
      try (java.util.stream.Stream<Path> paths = Files.walk(provider)) {
        for (final Path path :
            paths
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".class"))
                .sorted()
                .toList()) {
          try (InputStream input = Files.newInputStream(path)) {
            final String entry = provider.relativize(path).toString().replace('\\', '/');
            if (projectedEntries == null || projectedEntries.containsKey(entry)) {
              selection.readClass(input, entry, false);
            }
          }
        }
      }
    } else {
      scanArchive(provider, selection);
    }
  }

  private record ClassSelection(
      Map<String, String> projectedEntries, Set<String> removedClasses, ClassEntryVisitor visitor) {
    private boolean includes(final ZipEntry entry) {
      return !entry.isDirectory()
          && entry.getName().endsWith(".class")
          && (projectedEntries == null || projectedEntries.containsKey(entry.getName()));
    }

    private void readClass(final InputStream input, final String source, final boolean multiRelease)
        throws IOException {
      final String entry = projectedEntries == null ? source : projectedEntries.get(source);
      try {
        final ClassReader reader = new ClassReader(input);
        if (!removedClasses.contains(reader.getClassName().replace('/', '.'))) {
          final int tier =
              entry.startsWith(MultiReleaseEntryPath.PREFIX)
                  ? MultiReleaseEntryPath.parse(entry, false).release()
                  : 0;
          visitor.visit(reader, entry, tier, multiRelease);
        }
      } catch (IllegalArgumentException | IndexOutOfBoundsException exception) {
        throw new IOException("Malformed class entry: " + entry, exception);
      }
    }
  }

  private static void scanArchive(final Path path, final ClassSelection selection)
      throws IOException {
    final boolean multiRelease;
    try (JarFile archive = new JarFile(path.toFile(), false)) {
      multiRelease = archive.isMultiRelease();
      final List<? extends ZipEntry> entries =
          archive.stream().filter(selection::includes).toList();
      if (entries.stream().map(ZipEntry::getName).distinct().count() == entries.size()) {
        for (final ZipEntry entry : entries) {
          try (InputStream input = archive.getInputStream(entry)) {
            selection.readClass(input, entry.getName(), multiRelease);
          }
        }
        return;
      }
    }
    // ZipFile name lookup can hide an earlier physical entry with the same name.
    try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(path))) {
      for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
        if (selection.includes(entry)) {
          selection.readClass(zip, entry.getName(), multiRelease);
        }
      }
    }
  }

  private static void readDeclarations(
      final ClassReader reader,
      final String entry,
      final int tier,
      final Map<String, List<ClassInfo>> classes,
      final Map<String, Inner> inners,
      final boolean inspectMethods) {
    final String binary = reader.getClassName().replace('/', '.');
    final List<Method> methods = new ArrayList<>();
    reader.accept(
        new ClassVisitor(Opcodes.ASM9) {
          @Override
          public void visitInnerClass(
              final String name, final String outer, final String simple, int access) {
            if (outer != null && simple != null) {
              inners.put(name.replace('/', '.'), new Inner(outer.replace('/', '.'), simple));
            }
          }

          @Override
          public MethodVisitor visitMethod(
              final int access,
              final String name,
              final String descriptor,
              String signature,
              String[] exceptions) {
            if (inspectMethods) {
              methods.add(new Method(name, descriptor, access));
            }
            return null;
          }
        },
        ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    final String parent =
        reader.getSuperName() == null ? null : reader.getSuperName().replace('/', '.');
    final List<String> interfaces =
        java.util.Arrays.stream(reader.getInterfaces()).map(n -> n.replace('/', '.')).toList();
    classes
        .computeIfAbsent(binary, k -> new ArrayList<>())
        .add(new ClassInfo(binary, parent, interfaces, methods, reader.getAccess(), entry, tier));
  }

  private static String sourceName(
      final String binary, final Map<String, Inner> inners, final Set<String> visited) {
    final Inner inner = inners.get(binary);
    if (inner == null || !visited.add(binary)) {
      return binary;
    }
    return sourceName(inner.outer(), inners, visited) + "." + inner.simple();
  }

  private static Result assess(
      final ForbiddenSymbol symbol,
      final Map<String, List<ClassInfo>> classes,
      final Map<String, Set<String>> names,
      final Map<String, Inner> inners,
      final Set<Integer> tiers) {
    if (symbol.owner().endsWith("*")) {
      return wildcard(symbol.owner(), classes, names, inners);
    }
    final Set<String> owners = names.getOrDefault(symbol.owner(), Set.of());
    if (owners.size() > 1) {
      return new Result(Status.UNKNOWN, List.of(), "Ambiguous owner");
    }
    if (owners.isEmpty()) {
      return new Result(Status.PASS, List.of(), "Owner absent from provider");
    }
    final String owner = owners.iterator().next();
    final List<Evidence> evidence = new ArrayList<>();
    if (symbol.method() == null) {
      for (final ClassInfo info : classes.get(owner)) {
        evidence.add(new Evidence(owner, null, info.entry(), info.tier()));
      }
      return new Result(Status.VIOLATION, evidence, "Class present");
    }
    final Inner inner = inners.get(owner);
    final boolean includeConstructor =
        symbol.usesConstructorName() || (inner != null && symbol.method().equals(inner.simple()));
    boolean complete = true;
    for (final int tier : tiers) {
      if (classes.get(owner).stream().noneMatch(info -> info.tier() <= tier)) {
        continue;
      }
      complete &=
          collect(
              owner,
              symbol.method(),
              symbol.parameters(),
              includeConstructor,
              classes,
              inners,
              new HashSet<>(),
              evidence,
              tier,
              owner,
              true);
    }
    if (!evidence.isEmpty()) {
      return new Result(Status.VIOLATION, evidence, "Method declaration present", complete);
    }
    return new Result(
        complete ? Status.PASS : Status.UNKNOWN,
        evidence,
        complete ? "Method absent" : "Hierarchy incomplete");
  }

  private static Result wildcard(
      final String pattern,
      final Map<String, List<ClassInfo>> classes,
      final Map<String, Set<String>> names,
      final Map<String, Inner> inners) {
    final boolean recursive = pattern.endsWith("**");
    final int stars = recursive ? 2 : 1;
    final char separator = pattern.charAt(pattern.length() - stars - 1);
    final String base = pattern.substring(0, pattern.length() - stars - 1);
    final List<Evidence> evidence = new ArrayList<>();
    final Set<String> nestedOwners =
        new HashSet<>(separator == '$' ? names.getOrDefault(base, Set.of()) : Set.of());
    if (separator == '$') {
      for (final Inner inner : inners.values()) {
        if (sourceName(inner.outer(), inners, new HashSet<>()).equals(base)
            || inner.outer().equals(base)) {
          nestedOwners.add(inner.outer());
        }
      }
    }
    if (nestedOwners.size() > 1) {
      return new Result(Status.UNKNOWN, List.of(), "Ambiguous wildcard owner");
    }
    for (final String binary : classes.keySet().stream().sorted().toList()) {
      final boolean selected;
      if (separator == '$') {
        String parent = binary;
        boolean match = false;
        final Set<String> visited = new HashSet<>();
        while (inners.containsKey(parent) && visited.add(parent)) {
          parent = inners.get(parent).outer();
          if (nestedOwners.contains(parent)) {
            match = true;
            break;
          }
          if (!recursive) {
            break;
          }
        }
        selected = match;
      } else {
        final int dot = binary.lastIndexOf('.');
        final String pkg = dot < 0 ? "" : binary.substring(0, dot);
        selected =
            !inners.containsKey(binary)
                && (pkg.equals(base) || (recursive && pkg.startsWith(base + ".")));
      }
      if (selected) {
        for (final ClassInfo info : classes.get(binary)) {
          evidence.add(new Evidence(binary, null, info.entry(), info.tier()));
        }
      }
    }
    return new Result(
        evidence.isEmpty() ? Status.PASS : Status.VIOLATION,
        evidence,
        evidence.isEmpty() ? "Wildcard matched no classes" : "Wildcard matched classes");
  }

  private static boolean collect(
      final String name,
      final String method,
      final List<String> parameters,
      final boolean includeConstructor,
      final Map<String, List<ClassInfo>> classes,
      final Map<String, Inner> inners,
      final Set<String> visited,
      final List<Evidence> evidence,
      final int tier,
      final String requestedOwner,
      final boolean packagePath) {
    if (!visited.add(name + "\0" + packagePath)) {
      return true;
    }
    final List<ClassInfo> variants = classes.get(name);
    if (variants == null) {
      return "java.lang.Object".equals(name) && objectMethodAbsent(method, parameters, inners);
    }
    final int selectedTier =
        variants.stream().mapToInt(ClassInfo::tier).filter(t -> t <= tier).max().orElse(-1);
    if (selectedTier < 0) {
      return false;
    }
    boolean complete = true;
    for (final ClassInfo info : variants) {
      if (info.tier() != selectedTier) {
        continue;
      }
      for (final Method candidate : info.methods()) {
        final int access = candidate.access();
        final boolean inherited = !name.equals(requestedOwner);
        final boolean visible =
            !inherited
                || ((access & Opcodes.ACC_PRIVATE) == 0
                    && !((info.access() & Opcodes.ACC_INTERFACE) != 0
                        && (access & Opcodes.ACC_STATIC) != 0)
                    && ((access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0
                        || packagePath));
        final boolean matchesName =
            candidate.name().equals(method)
                || (includeConstructor && !inherited && "<init>".equals(candidate.name()));
        if (visible && matchesName && matches(candidate.descriptor(), parameters, inners)) {
          evidence.add(
              new Evidence(info.name(), candidate.descriptor(), info.entry(), info.tier()));
        }
        if (visible
            && matchesName
            && unresolvedParameters(candidate.descriptor(), parameters, inners)) {
          complete = false;
        }
      }
      if (info.parent() != null) {
        complete &=
            collect(
                info.parent(),
                method,
                parameters,
                false,
                classes,
                inners,
                visited,
                evidence,
                tier,
                requestedOwner,
                packagePath && packageName(name).equals(packageName(info.parent())));
      }
      for (final String parent : info.interfaces()) {
        complete &=
            collect(
                parent,
                method,
                parameters,
                false,
                classes,
                inners,
                visited,
                evidence,
                tier,
                requestedOwner,
                packagePath && packageName(name).equals(packageName(parent)));
      }
    }
    return complete;
  }

  private static boolean objectMethodAbsent(
      final String method, final List<String> parameters, final Map<String, Inner> inners) {
    for (final java.lang.reflect.Method candidate : Object.class.getDeclaredMethods()) {
      final int access = candidate.getModifiers();
      if ((java.lang.reflect.Modifier.isPublic(access)
              || java.lang.reflect.Modifier.isProtected(access))
          && !java.lang.reflect.Modifier.isStatic(access)
          && candidate.getName().equals(method)
          && matches(Type.getMethodDescriptor(candidate), parameters, inners)) {
        return false;
      }
    }
    return true;
  }

  private static String packageName(final String binary) {
    final int dot = binary.lastIndexOf('.');
    return dot < 0 ? "" : binary.substring(0, dot);
  }

  private static boolean unresolvedParameters(
      final String descriptor, final List<String> parameters, final Map<String, Inner> inners) {
    final Type[] arguments = Type.getArgumentTypes(descriptor);
    if (arguments.length != parameters.size()) {
      return false;
    }
    for (int i = 0; i < arguments.length; i++) {
      final Type type =
          arguments[i].getSort() == Type.ARRAY ? arguments[i].getElementType() : arguments[i];
      if (type.getSort() == Type.OBJECT
          && type.getClassName().contains("$")
          && !inners.containsKey(type.getClassName())
          && parameters.get(i).contains(".")) {
        return true;
      }
    }
    return false;
  }

  private static boolean matches(
      final String descriptor, final List<String> parameters, final Map<String, Inner> inners) {
    final Type[] arguments = Type.getArgumentTypes(descriptor);
    if (arguments.length != parameters.size()) {
      return false;
    }
    for (int i = 0; i < arguments.length; i++) {
      Type element = arguments[i];
      String suffix = "";
      if (element.getSort() == Type.ARRAY) {
        suffix = "[]".repeat(element.getDimensions());
        element = element.getElementType();
      }
      final String name = element.getClassName();
      if (!(name + suffix).equals(parameters.get(i))
          && !(sourceName(name, inners, new HashSet<>()) + suffix).equals(parameters.get(i))) {
        return false;
      }
    }
    return true;
  }
}
