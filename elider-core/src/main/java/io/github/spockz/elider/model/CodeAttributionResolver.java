/* WHY: Maps generic code claims to class families. */

package io.github.spockz.elider.model;

import io.github.spockz.elider.scanner.JarSourceFileIndex;
import io.github.spockz.elider.scanner.JarSourceFileIndex.ClassSourceFile;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.objectweb.asm.Type;

/** Resolves generic code claims to artifact class families. */
@SuppressWarnings({
  "PMD.GodClass",
  "PMD.TooManyMethods",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.NPathComplexity",
  "PMD.AvoidLiteralsInIfCondition"
})
public final class CodeAttributionResolver {
  /** Validated binary class-name syntax supported by code locators. */
  private static final Pattern BINARY_NAME =
      Pattern.compile("[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)*");

  /** JVM grammar for one non-void field descriptor. */
  private static final String FIELD_DESCRIPTOR = "\\[*[BCDFIJSZ]|\\[*L[A-Za-z0-9_$/]+;";

  /** JVM grammar for one complete method descriptor. */
  private static final Pattern METHOD_DESCRIPTOR =
      Pattern.compile("\\((?:" + FIELD_DESCRIPTOR + ")*\\)(?:V|" + FIELD_DESCRIPTOR + ")");

  /** Method names accepted by routine locators. */
  private static final Pattern METHOD_NAME =
      Pattern.compile("(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)");

  private CodeAttributionResolver() {}

  /** Resolves each claim independently against one immutable class-file index. */
  public static Result resolve(
      final List<CodeClaim> claims,
      final JarSourceFileIndex sourceIndex,
      final boolean assumeConventionalJavaSourceLayout) {
    Objects.requireNonNull(claims, "claims");
    Objects.requireNonNull(sourceIndex, "sourceIndex");
    final List<DeclarationResult> results =
        claims.stream()
            .map(
                claim ->
                    resolveOne(
                        Objects.requireNonNull(claim, "claim"),
                        sourceIndex,
                        assumeConventionalJavaSourceLayout))
            .toList();
    return new Result(results);
  }

  private static DeclarationResult resolveOne(
      final CodeClaim claim,
      final JarSourceFileIndex sourceIndex,
      final boolean assumeConventionalJavaSourceLayout) {
    if (claim.kind() == CodeClaim.Kind.HEURISTIC) {
      return result(claim, Status.REVIEW_LEAD, Set.of(), List.of(Reason.HEURISTIC_REQUIRES_REVIEW));
    }
    return switch (claim.reference().kind()) {
      case CLASS_NAME -> resolveClass(claim, sourceIndex);
      case SOURCE_FILE -> resolveSourceFile(claim, sourceIndex, assumeConventionalJavaSourceLayout);
      case ROUTINE -> resolveRoutine(claim, sourceIndex);
    };
  }

  private static DeclarationResult resolveClass(
      final CodeClaim claim, final JarSourceFileIndex sourceIndex) {
    final String name = claim.reference().value();
    if (!BINARY_NAME.matcher(name).matches()) {
      return unresolved(claim, Reason.INVALID_CLASS_NAME);
    }
    final boolean present =
        sourceIndex.classFiles().stream()
            .anyMatch(classFile -> classFile.classEntry().equals(name));
    if (!present) {
      return unresolved(claim, Reason.CLASS_NOT_FOUND);
    }
    return result(claim, Status.RESOLVED, family(sourceIndex.classFiles(), name), List.of());
  }

  private static DeclarationResult resolveSourceFile(
      final CodeClaim claim,
      final JarSourceFileIndex sourceIndex,
      final boolean assumeConventionalJavaSourceLayout) {
    final Set<String> paths =
        SourceClaimPathMatcher.packageRelativeSourcePaths(
            claim.reference(), assumeConventionalJavaSourceLayout);
    final boolean hasDisallowedRoot =
        SourceClaimPathMatcher.containsConventionalSourceRoot(claim.reference())
            && !assumeConventionalJavaSourceLayout;
    if (paths.isEmpty()) {
      return unresolved(
          claim,
          hasDisallowedRoot
              ? Reason.SOURCE_ROOT_REQUIRES_LAYOUT_ASSUMPTION
              : Reason.INVALID_SOURCE_PATH);
    }

    final Set<String> matched = new TreeSet<>();
    final Set<String> packages = new TreeSet<>();
    final Set<String> candidateOwners = new TreeSet<>();
    for (final String path : paths) {
      final int separator = path.lastIndexOf('/');
      final String packageName = path.substring(0, separator).replace('/', '.');
      packages.add(packageName);
      final String basename = path.substring(separator + 1);
      final String candidateOwner =
          packageName + "." + basename.substring(0, basename.length() - ".java".length());
      candidateOwners.add(candidateOwner);
      for (final ClassSourceFile classFile : sourceIndex.classFiles()) {
        if (basename.equals(classFile.sourceFile())
            && packageName.equals(SourceClaimPathMatcher.classPackage(classFile.classEntry()))) {
          matched.add(classFile.classEntry());
        }
      }
    }

    final boolean possibleUnknownSiblings =
        sourceIndex.classFiles().stream()
            .anyMatch(
                classFile ->
                    classFile.sourceFile() == null
                        && packages.contains(
                            SourceClaimPathMatcher.classPackage(classFile.classEntry())));
    if (matched.isEmpty() && assumeConventionalJavaSourceLayout) {
      for (final String owner : candidateOwners) {
        final boolean ownerHasUnknownSource =
            sourceIndex.classFiles().stream()
                .anyMatch(
                    classFile ->
                        classFile.classEntry().equals(owner) && classFile.sourceFile() == null);
        if (ownerHasUnknownSource) {
          matched.addAll(unknownSourceFamily(sourceIndex.classFiles(), owner));
        }
      }
    }
    if (matched.isEmpty()) {
      return unresolved(claim, Reason.SOURCE_FILE_NOT_FOUND);
    }

    boolean conflictingNestedMetadata = false;
    for (final String owner : List.copyOf(matched)) {
      final String expectedSource = sourceForOwner(sourceIndex.classFiles(), owner);
      final String nestedPrefix = owner + "$";
      for (final ClassSourceFile classFile : sourceIndex.classFiles()) {
        if (classFile.classEntry().startsWith(nestedPrefix)) {
          matched.add(classFile.classEntry());
          if (classFile.sourceFile() != null
              && expectedSource != null
              && !expectedSource.equals(classFile.sourceFile())) {
            conflictingNestedMetadata = true;
          }
        }
      }
    }

    final List<Reason> reasons = new ArrayList<>();
    if (possibleUnknownSiblings) {
      reasons.add(Reason.POSSIBLE_UNIDENTIFIED_FILE_SIBLING);
    }
    if (conflictingNestedMetadata) {
      reasons.add(Reason.CONFLICTING_NESTED_SOURCE_FILE_METADATA);
    }
    final boolean complete = reasons.isEmpty();
    return result(claim, complete ? Status.RESOLVED : Status.PARTIAL, matched, reasons);
  }

  private static String sourceForOwner(
      final Collection<ClassSourceFile> classFiles, final String owner) {
    return classFiles.stream()
        .filter(classFile -> classFile.classEntry().equals(owner))
        .map(ClassSourceFile::sourceFile)
        .filter(Objects::nonNull)
        .findFirst()
        .orElse(null);
  }

  private static Set<String> unknownSourceFamily(
      final Collection<ClassSourceFile> classFiles, final String owner) {
    final String nestedPrefix = owner + "$";
    final Set<String> names = new TreeSet<>();
    classFiles.stream()
        .filter(classFile -> classFile.sourceFile() == null)
        .map(ClassSourceFile::classEntry)
        .filter(name -> name.equals(owner) || name.startsWith(nestedPrefix))
        .forEach(names::add);
    return names;
  }

  private static DeclarationResult resolveRoutine(
      final CodeClaim claim, final JarSourceFileIndex sourceIndex) {
    final RoutineLocator locator = RoutineLocator.parse(claim.reference().value());
    if (locator == null) {
      return unresolved(claim, Reason.UNSUPPORTED_ROUTINE_SYNTAX);
    }
    final List<String> candidates = new ArrayList<>();
    if (locator.owner() == null) {
      sourceIndex.classFiles().stream()
          .filter(classFile -> hasMethod(classFile, locator))
          .map(ClassSourceFile::classEntry)
          .distinct()
          .sorted()
          .forEach(candidates::add);
    } else if (locator.owner().contains(".")) {
      final boolean ownerExists =
          sourceIndex.classFiles().stream()
              .anyMatch(classFile -> classFile.classEntry().equals(locator.owner()));
      if (!ownerExists) {
        return unresolved(claim, Reason.ROUTINE_OWNER_NOT_FOUND);
      }
      if (sourceIndex.classFiles().stream()
          .anyMatch(
              classFile ->
                  classFile.classEntry().equals(locator.owner())
                      && hasMethod(classFile, locator))) {
        candidates.add(locator.owner());
      } else {
        return unresolved(claim, Reason.ROUTINE_METHOD_NOT_FOUND);
      }
    } else {
      final List<String> namedOwners =
          sourceIndex.classFiles().stream()
              .map(ClassSourceFile::classEntry)
              .filter(owner -> simpleName(owner).equals(locator.owner()))
              .distinct()
              .sorted()
              .toList();
      namedOwners.stream()
          .filter(
              owner ->
                  sourceIndex.classFiles().stream()
                      .anyMatch(
                          classFile ->
                              classFile.classEntry().equals(owner)
                                  && hasMethod(classFile, locator)))
          .forEach(candidates::add);
      if (candidates.isEmpty() && namedOwners.isEmpty()) {
        return unresolved(claim, Reason.ROUTINE_OWNER_NOT_FOUND);
      }
      if (candidates.isEmpty()) {
        return unresolved(claim, Reason.ROUTINE_METHOD_NOT_FOUND);
      }
    }
    if (candidates.isEmpty()) {
      return unresolved(claim, Reason.ROUTINE_METHOD_NOT_FOUND);
    }
    if (candidates.size() != 1) {
      return unresolved(claim, Reason.ROUTINE_OWNER_AMBIGUOUS);
    }
    return result(
        claim, Status.RESOLVED, family(sourceIndex.classFiles(), candidates.getFirst()), List.of());
  }

  private static boolean hasMethod(final ClassSourceFile classFile, final RoutineLocator locator) {
    return classFile.declaredMethods().stream()
        .anyMatch(
            method ->
                method.name().equals(locator.methodName())
                    && (locator.descriptor() == null
                        || locator.descriptor().equals(method.descriptor())));
  }

  private static String simpleName(final String binaryName) {
    final int separator = binaryName.lastIndexOf('.');
    return binaryName.substring(separator + 1);
  }

  private static Set<String> family(
      final Collection<ClassSourceFile> classFiles, final String owner) {
    final Set<String> names = new TreeSet<>();
    final String nestedPrefix = owner + "$";
    classFiles.stream()
        .map(ClassSourceFile::classEntry)
        .filter(name -> name.equals(owner) || name.startsWith(nestedPrefix))
        .forEach(names::add);
    return java.util.Collections.unmodifiableSet(names);
  }

  private static DeclarationResult unresolved(final CodeClaim claim, final Reason reason) {
    return result(claim, Status.UNRESOLVED, Set.of(), List.of(reason));
  }

  private static DeclarationResult result(
      final CodeClaim claim,
      final Status status,
      final Set<String> family,
      final List<Reason> reasons) {
    return new DeclarationResult(claim, status, family, reasons);
  }

  /** Result for one effective code declaration. */
  public record DeclarationResult(
      CodeClaim claim, Status status, Set<String> classFamily, List<Reason> reasons) {
    /** Freezes class family and diagnostics. */
    public DeclarationResult {
      Objects.requireNonNull(claim, "claim");
      Objects.requireNonNull(status, "status");
      classFamily = java.util.Collections.unmodifiableSet(new TreeSet<>(classFamily));
      reasons = List.copyOf(reasons);
      if ((status == Status.UNRESOLVED || status == Status.REVIEW_LEAD) && !classFamily.isEmpty()) {
        throw new IllegalArgumentException(
            "unresolved or heuristic claim cannot have a class family");
      }
      if ((status == Status.UNRESOLVED || status == Status.PARTIAL || status == Status.REVIEW_LEAD)
          && reasons.isEmpty()) {
        throw new IllegalArgumentException("incomplete attribution requires a reason");
      }
      if ((status == Status.RESOLVED || status == Status.PARTIAL) && classFamily.isEmpty()) {
        throw new IllegalArgumentException("attributed declarations require a class family");
      }
      if (status == Status.RESOLVED && !reasons.isEmpty()) {
        throw new IllegalArgumentException("resolved declarations cannot have incomplete reasons");
      }
      if ((status == Status.REVIEW_LEAD) != (claim.kind() == CodeClaim.Kind.HEURISTIC)) {
        throw new IllegalArgumentException("heuristics must remain review leads");
      }
    }
  }

  /** Immutable outcomes in input declaration order. */
  public record Result(List<DeclarationResult> declarations) {
    /** Freezes the ordered per-declaration outcomes. */
    public Result {
      declarations = List.copyOf(declarations);
    }
  }

  /** Completeness and review state for one declaration. */
  public enum Status {
    RESOLVED,
    PARTIAL,
    UNRESOLVED,
    REVIEW_LEAD
  }

  /** Stable explanation for unresolved, partial, or review-only attribution. */
  public enum Reason {
    HEURISTIC_REQUIRES_REVIEW,
    ARCHIVE_UNAVAILABLE,
    INVALID_CLASS_NAME,
    CLASS_NOT_FOUND,
    INVALID_SOURCE_PATH,
    SOURCE_ROOT_REQUIRES_LAYOUT_ASSUMPTION,
    SOURCE_FILE_NOT_FOUND,
    POSSIBLE_UNIDENTIFIED_FILE_SIBLING,
    CONFLICTING_NESTED_SOURCE_FILE_METADATA,
    UNSUPPORTED_ROUTINE_SYNTAX,
    ROUTINE_OWNER_NOT_FOUND,
    ROUTINE_METHOD_NOT_FOUND,
    ROUTINE_OWNER_AMBIGUOUS
  }

  private record RoutineLocator(String owner, String methodName, String descriptor) {
    private static RoutineLocator parse(final String value) {
      final String text = value.trim();
      final int descriptorStart = text.indexOf('(');
      final String locator = descriptorStart < 0 ? text : text.substring(0, descriptorStart);
      final String descriptor = descriptorStart < 0 ? null : text.substring(descriptorStart);
      if (descriptor != null && !validDescriptor(descriptor)) {
        return null;
      }
      final int ownerSeparator = Math.max(locator.lastIndexOf('.'), locator.lastIndexOf('#'));
      final String owner = ownerSeparator < 0 ? null : locator.substring(0, ownerSeparator);
      final String methodName = locator.substring(ownerSeparator + 1);
      if (!METHOD_NAME.matcher(methodName).matches()
          || (owner != null && !BINARY_NAME.matcher(owner).matches())) {
        return null;
      }
      return new RoutineLocator(owner, methodName, descriptor);
    }

    private static boolean validDescriptor(final String descriptor) {
      if (!METHOD_DESCRIPTOR.matcher(descriptor).matches()) {
        return false;
      }
      try {
        return Type.getMethodType(descriptor).getDescriptor().equals(descriptor);
      } catch (final IllegalArgumentException exception) {
        return false;
      }
    }
  }
}
