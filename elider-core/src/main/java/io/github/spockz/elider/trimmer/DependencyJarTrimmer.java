/* WHY: Computes per-artifact class retention with ProGuard Core so a retained dependency can be
 * reduced without merging it with sibling artifacts. */

package io.github.spockz.elider.trimmer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import proguard.classfile.ClassPool;
import proguard.classfile.Clazz;
import proguard.classfile.attribute.Attribute;
import proguard.classfile.attribute.RecordAttribute;
import proguard.classfile.attribute.RecordComponentInfo;
import proguard.classfile.attribute.visitor.RecordComponentInfoVisitor;
import proguard.classfile.constant.Constant;
import proguard.classfile.constant.DynamicConstant;
import proguard.classfile.constant.RefConstant;
import proguard.classfile.util.ClassReferenceInitializer;
import proguard.classfile.util.ClassSuperHierarchyInitializer;
import proguard.classfile.util.InvalidReferenceVisitor;
import proguard.classfile.visitor.ClassVisitor;
import proguard.classfile.visitor.ReferencedClassVisitor;
import proguard.io.util.IOUtil;

/** Computes class retention from roots; it does not discover them. */
@SuppressWarnings({
  "PMD.ExcessiveImports",
  "PMD.GodClass",
  "PMD.CyclomaticComplexity",
  "PMD.AvoidInstantiatingObjectsInLoops",
  "PMD.UseConcurrentHashMap",
  "PMD.CompareObjectsWithEquals",
  "PMD.AvoidCatchingGenericException"
})
public final class DependencyJarTrimmer {
  /** Creates a dependency trimmer backed by ProGuard Core's class-file model. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  public DependencyJarTrimmer() {}

  /**
   * Computes closure from caller roots and flat, non-MR sibling JARs.
   *
   * @param libraryClassPath flat sibling JAR paths
   * @param retainedRoots complete caller roots; empty retains all candidate classes
   */
  public TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeInternal(
        candidateJar, libraryClassPath, new ClassPool(), retainedRoots, false, Set.of());
  }

  /**
   * Adds the explicitly selected compiler/JDK API pool to closure analysis.
   *
   * @param platformLibraryPool API classes for the effective compiler release
   */
  public TrimAnalysis analyze(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeInternal(
        candidateJar, libraryClassPath, platformLibraryPool, retainedRoots, false, Set.of());
  }

  /**
   * Computes links from every class in an unchanged pass-through archive.
   *
   * <p>Unresolved links from unchanged classes are ignored.
   *
   * <p>Absent classes cannot identify candidates. Sibling gaps remain fatal.
   */
  public TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots)
      throws IOException {
    return analyzeUnchangedPassThrough(
        candidateJar, libraryClassPath, platformLibraryPool, retainedRoots, Set.of());
  }

  /** Computes closure for one unchanged pass-through archive and its sibling owners. */
  public TrimAnalysis analyzeUnchangedPassThrough(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    Objects.requireNonNull(unchangedPassThroughClassNames, "unchangedPassThroughClassNames");
    final Set<String> toleratedNames = new HashSet<>();
    unchangedPassThroughClassNames.forEach(name -> toleratedNames.add(name.replace('.', '/')));
    return analyzeInternal(
        candidateJar, libraryClassPath, platformLibraryPool, retainedRoots, true, toleratedNames);
  }

  /** Computes candidate closure with unchanged-library tolerance. */
  public TrimAnalysis analyzeWithUnchangedPassThroughLibraries(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final Collection<String> unchangedPassThroughClassNames)
      throws IOException {
    Objects.requireNonNull(unchangedPassThroughClassNames, "unchangedPassThroughClassNames");
    final Set<String> toleratedNames = new HashSet<>();
    unchangedPassThroughClassNames.forEach(name -> toleratedNames.add(name.replace('.', '/')));
    return analyzeInternal(
        candidateJar, libraryClassPath, platformLibraryPool, retainedRoots, false, toleratedNames);
  }

  @SuppressWarnings({"PMD.NcssCount", "PMD.CognitiveComplexity", "PMD.NPathComplexity"})
  private TrimAnalysis analyzeInternal(
      final Path candidateJar,
      final Collection<Path> libraryClassPath,
      final ClassPool platformLibraryPool,
      final Collection<String> retainedRoots,
      final boolean tolerateUnresolvedProgramReferences,
      final Set<String> toleratedUnresolvedLibraryClasses)
      throws IOException {
    Objects.requireNonNull(candidateJar, "candidateJar");
    Objects.requireNonNull(libraryClassPath, "libraryClassPath");
    Objects.requireNonNull(platformLibraryPool, "platformLibraryPool");
    Objects.requireNonNull(retainedRoots, "retainedRoots");
    if (!Files.isRegularFile(candidateJar)) {
      throw new IllegalArgumentException("Candidate JAR is not a regular file: " + candidateJar);
    }
    final Set<String> expectedProgramClasses = validateArchive(candidateJar, true);

    final ClassPool programPool = IOUtil.read(candidateJar.toFile(), false);
    if (programPool.size() == 0) {
      throw new IllegalArgumentException("Candidate JAR contains no classes: " + candidateJar);
    }
    final Set<String> ingestedProgramClasses = new TreeSet<>();
    programPool.classNames().forEachRemaining(ingestedProgramClasses::add);
    if (!ingestedProgramClasses.equals(expectedProgramClasses)) {
      throw new IOException(
          "ProGuard Core ingested classes outside the candidate JAR's direct entries: "
              + ingestedProgramClasses);
    }

    final ClassPool libraryPool = new ClassPool();
    final Set<String> platformLibraryClasses = new HashSet<>();
    for (final Path libraryPath : libraryClassPath) {
      if (libraryPath == null || !Files.exists(libraryPath)) {
        throw new IllegalArgumentException(
            "Library classpath entry does not exist: " + libraryPath);
      }
      final Set<String> expectedLibraryClasses = validateArchive(libraryPath, false);
      final ClassPool nextPool = IOUtil.read(libraryPath.toFile(), true);
      final Set<String> ingestedLibraryClasses = new TreeSet<>();
      nextPool.classNames().forEachRemaining(ingestedLibraryClasses::add);
      if (!ingestedLibraryClasses.equals(expectedLibraryClasses)) {
        throw new IOException(
            "ProGuard Core ingested classes outside the library JAR's direct entries: "
                + libraryPath);
      }
      for (final Clazz libraryClass : nextPool.classes()) {
        if (programPool.getClass(libraryClass.getName()) == null
            && libraryPool.getClass(libraryClass.getName()) == null) {
          libraryPool.addClass(libraryClass);
        }
      }
    }
    for (final Clazz platformClass : platformLibraryPool.classes()) {
      if (programPool.getClass(platformClass.getName()) == null
          && libraryPool.getClass(platformClass.getName()) == null) {
        libraryPool.addClass(platformClass);
        platformLibraryClasses.add(platformClass.getName());
      }
    }

    final Function<String, Clazz> classLookup =
        className -> {
          final Clazz programClass = programPool.getClass(className);
          return programClass == null ? libraryPool.getClass(className) : programClass;
        };
    final Map<String, Set<String>> signaturePolymorphicDescriptorTypes = new HashMap<>();
    final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver =
        new SignaturePolymorphicReferenceResolver(signaturePolymorphicDescriptorTypes, classLookup);
    final Map<String, Set<String>> unresolvedLibraryReferences = new HashMap<>();
    final InvalidReferenceVisitor libraryInvalidReferenceVisitor =
        new RecordingLibraryReferenceVisitor(
            unresolvedLibraryReferences, signaturePolymorphicResolver);
    final ClassSuperHierarchyInitializer libraryHierarchyInitializer =
        new ClassSuperHierarchyInitializer(
            programPool, libraryPool, libraryInvalidReferenceVisitor);
    libraryPool.classesAccept(
        new ClassVisitor() {
          @Override
          public void visitAnyClass(final Clazz clazz) {
            clazz.accept(libraryHierarchyInitializer);
          }
        });
    libraryPool.classesAccept(
        new ClassReferenceInitializer(
            programPool, libraryPool, false, libraryInvalidReferenceVisitor));

    final Map<String, Set<String>> unresolvedReferences = new HashMap<>();
    final InvalidReferenceVisitor invalidReferenceVisitor =
        new RecordingInvalidReferenceVisitor(unresolvedReferences, signaturePolymorphicResolver);
    programPool.classesAccept(
        new ClassSuperHierarchyInitializer(programPool, libraryPool, invalidReferenceVisitor));
    programPool.classesAccept(
        new ClassReferenceInitializer(programPool, libraryPool, false, invalidReferenceVisitor));
    final Set<String> roots = normalizeRoots(retainedRoots);
    if (roots.isEmpty()) {
      final Set<String> allProgramClasses = new TreeSet<>();
      programPool.classNames().forEachRemaining(allProgramClasses::add);
      return new TrimAnalysis(programPool.size(), allProgramClasses, roots, Set.of());
    }
    final Set<String> missingRoots = new TreeSet<>();
    for (final String root : roots) {
      if (programPool.getClass(root) == null) {
        missingRoots.add(root);
      }
    }
    if (!missingRoots.isEmpty()) {
      throw new IllegalArgumentException(
          "Retained roots are not in candidate JAR: " + missingRoots);
    }

    final Set<Clazz> visited = new LinkedHashSet<>();
    final Deque<Clazz> pending = new java.util.ArrayDeque<>();
    final Set<Clazz> visitedLibraries = new HashSet<>();
    roots.forEach(root -> pending.add(programPool.getClass(root)));
    final ClassVisitor collectReferencedClasses =
        new ClassVisitor() {
          @Override
          public void visitAnyClass(final Clazz clazz) {
            if (programPool.getClass(clazz.getName()) == clazz
                || (libraryPool.getClass(clazz.getName()) == clazz
                    && !platformLibraryClasses.contains(clazz.getName()))) {
              pending.add(clazz);
            }
          }
        };
    while (!pending.isEmpty()) {
      final Clazz current = pending.removeFirst();
      if (programPool.getClass(current.getName()) == current) {
        if (!visited.add(current)) {
          continue;
        }
        if (!tolerateUnresolvedProgramReferences
            && unresolvedReferences.containsKey(current.getName())) {
          throw new UnresolvedReferenceException(
              candidateJar, unresolvedReferences.get(current.getName()));
        }
        current.accept(new CompleteReferencedClassVisitor(collectReferencedClasses, classLookup));
        signaturePolymorphicResolver.enqueueDescriptorTypes(current, collectReferencedClasses);
      } else if (!platformLibraryClasses.contains(current.getName())
          && libraryPool.getClass(current.getName()) == current
          && visitedLibraries.add(current)) {
        if (unresolvedLibraryReferences.containsKey(current.getName())
            && !toleratedUnresolvedLibraryClasses.contains(current.getName())) {
          throw new UnresolvedReferenceException(
              candidateJar, unresolvedLibraryReferences.get(current.getName()));
        }
        current.accept(new CompleteReferencedClassVisitor(collectReferencedClasses, classLookup));
        signaturePolymorphicResolver.enqueueDescriptorTypes(current, collectReferencedClasses);
      }
    }

    final Set<String> retainedClasses = new TreeSet<>();
    visited.forEach(clazz -> retainedClasses.add(clazz.getName()));
    final Set<String> reachableLibraryClasses = new TreeSet<>();
    visitedLibraries.forEach(clazz -> reachableLibraryClasses.add(clazz.getName()));
    return new TrimAnalysis(programPool.size(), retainedClasses, roots, reachableLibraryClasses);
  }

  private static Set<String> normalizeRoots(final Collection<String> roots) {
    final Set<String> normalized = new LinkedHashSet<>();
    for (final String root : roots) {
      if (root == null || root.isBlank()) {
        throw new IllegalArgumentException("Retained roots must not contain null or blank names");
      }
      final String name = root.replace('.', '/');
      if (name.startsWith("[") || name.endsWith(".class") || name.contains(";")) {
        throw new IllegalArgumentException(
            "Root must be a class name, not a descriptor or path: " + root);
      }
      normalized.add(name);
    }
    return normalized;
  }

  @SuppressWarnings("PMD.CognitiveComplexity")
  private static Set<String> validateArchive(final Path archivePath, final boolean candidate)
      throws IOException {
    final Path fileName = archivePath.getFileName();
    if (!candidate
        && (Files.isDirectory(archivePath)
            || fileName == null
            || !fileName.toString().endsWith(".jar"))) {
      throw new IOException("Only flat sibling JAR libraries are supported: " + archivePath);
    }
    final Set<String> classNames = new HashSet<>();
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      final java.util.Enumeration<JarEntry> entries = archive.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        final String entryName = entry.getName();
        if (entry.isDirectory() || !entryName.endsWith(".class")) {
          if (isNestedArchive(entryName)) {
            throw new IOException("Nested archives are not supported: " + entryName);
          }
          continue;
        }
        if (candidate && "module-info.class".equals(entryName)) {
          throw new IOException("Cannot safely trim an explicit modular JAR: " + archivePath);
        }
        if (isVersionedModuleDescriptor(entryName)) {
          try (java.io.InputStream input = archive.getInputStream(entry)) {
            if (!"module-info".equals(new ClassReader(input).getClassName())) {
              throw new IOException(
                  "Invalid versioned module descriptor in classpath JAR: " + archivePath);
            }
          } catch (final RuntimeException exception) {
            throw new IOException(
                "Could not read versioned module descriptor in " + archivePath, exception);
          }
          continue;
        }
        if (entryName.startsWith("META-INF/versions/")) {
          final String kind = candidate ? "candidate" : "library";
          throw new IOException(
              "Cannot safely resolve a multi-release " + kind + " JAR: " + archivePath);
        }
        final String declaredName;
        try (java.io.InputStream input = archive.getInputStream(entry)) {
          declaredName = new ClassReader(input).getClassName();
        } catch (final RuntimeException exception) {
          throw new IOException("Could not read class entry " + entryName, exception);
        }
        if (!entryName.equals(declaredName + ".class")) {
          throw new IOException(
              "Class entry path does not match its declared name in "
                  + archivePath
                  + ": "
                  + entryName
                  + " -> "
                  + declaredName);
        }
        if (!classNames.add(declaredName)) {
          throw new IOException(
              "Duplicate class definition in " + archivePath + ": " + declaredName);
        }
      }
    }
    return classNames;
  }

  /** Package scope shares the accepted archive rule with the sanitizer. */
  @SuppressWarnings("PMD.CommentDefaultAccessModifier")
  static boolean isVersionedModuleDescriptor(final String entryName) {
    return entryName.matches("META-INF/versions/[0-9]+/module-info\\.class");
  }

  private static boolean isNestedArchive(final String entryName) {
    return entryName.endsWith(".jar")
        || entryName.endsWith(".zip")
        || entryName.endsWith(".war")
        || entryName.endsWith(".ear");
  }

  /** Immutable analysis result preserving roots for audit callers. */
  public record TrimAnalysis(
      int totalClasses,
      Set<String> retainedClasses,
      Set<String> roots,
      Set<String> reachableLibraryClasses) {
    /** Preserves the prior constructor for existing callers. */
    public TrimAnalysis(
        final int totalClasses, final Set<String> retainedClasses, final Set<String> roots) {
      this(totalClasses, retainedClasses, roots, Set.of());
    }

    /** Copies the result sets into immutable snapshots. */
    public TrimAnalysis {
      retainedClasses = Set.copyOf(retainedClasses);
      roots = Set.copyOf(roots);
      reachableLibraryClasses = Set.copyOf(reachableLibraryClasses);
    }
  }

  /** Reports unresolved links so callers cannot emit an incomplete JAR. */
  public static final class UnresolvedReferenceException extends IOException {
    private static final long serialVersionUID = 1L;

    /** Creates a failure listing unresolved candidate references. */
    public UnresolvedReferenceException(final Path candidateJar, final Set<String> references) {
      super("Cannot safely trim " + candidateJar + "; unresolved references: " + references);
    }
  }

  /** Adds metadata links Core 9.1.10 omits from its general visitor. */
  private static final class CompleteReferencedClassVisitor extends ReferencedClassVisitor
      implements RecordComponentInfoVisitor {
    /** Receives newly reached candidate and sibling classes. */
    private final ClassVisitor classVisitor;

    /** Resolves descriptor names against the merged analysis pools. */
    private final Function<String, Clazz> classLookup;

    private CompleteReferencedClassVisitor(
        final ClassVisitor classVisitor, final Function<String, Clazz> classLookup) {
      super(classVisitor);
      this.classVisitor = classVisitor;
      this.classLookup = classLookup;
    }

    @Override
    public void visitAnyConstant(final Clazz clazz, final Constant constant) {
      if (constant instanceof DynamicConstant dynamicConstant) {
        dynamicConstant.referencedClassesAccept(classVisitor);
        dynamicConstant.bootstrapMethodHandleAccept(clazz, this);
      }
      super.visitAnyConstant(clazz, constant);
    }

    @Override
    public void visitAnyRefConstant(final Clazz clazz, final RefConstant refConstant) {
      super.visitAnyRefConstant(clazz, refConstant);
      visitDescriptorClasses(refConstant.getType(clazz), classLookup, classVisitor);
    }

    @Override
    public void visitAnyAttribute(final Clazz clazz, final Attribute attribute) {
      if (attribute instanceof RecordAttribute recordAttribute) {
        recordAttribute.componentsAccept(clazz, this);
      }
      super.visitAnyAttribute(clazz, attribute);
    }

    @Override
    public void visitRecordComponentInfo(
        final Clazz clazz, final RecordComponentInfo recordComponentInfo) {
      recordComponentInfo.referencedFieldAccept(clazz, this);
      recordComponentInfo.attributesAccept(clazz, this);
    }
  }

  private static void visitDescriptorClasses(
      final String descriptor,
      final Function<String, Clazz> classLookup,
      final ClassVisitor classVisitor) {
    final Type descriptorType = Type.getType(descriptor);
    if (descriptorType.getSort() == Type.METHOD) {
      visitType(descriptorType.getReturnType(), classLookup, classVisitor);
      for (final Type argumentType : descriptorType.getArgumentTypes()) {
        visitType(argumentType, classLookup, classVisitor);
      }
    } else {
      visitType(descriptorType, classLookup, classVisitor);
    }
  }

  private static void visitType(
      final Type type, final Function<String, Clazz> classLookup, final ClassVisitor classVisitor) {
    final Type elementType = type.getSort() == Type.ARRAY ? type.getElementType() : type;
    if (elementType.getSort() == Type.OBJECT) {
      final Clazz referencedClass = classLookup.apply(elementType.getInternalName());
      if (referencedClass != null) {
        classVisitor.visitAnyClass(referencedClass);
      }
    }
  }

  /** Records missing candidate links before closure starts. */
  private static final class RecordingInvalidReferenceVisitor implements InvalidReferenceVisitor {
    /** Stores missing reference descriptions. */
    private final Map<String, Set<String>> unresolvedReferences;

    /** Handles legal signature-polymorphic links omitted by Core's visitor. */
    private final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver;

    private RecordingInvalidReferenceVisitor(
        final Map<String, Set<String>> unresolvedReferences,
        final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver) {
      this.unresolvedReferences = unresolvedReferences;
      this.signaturePolymorphicResolver = signaturePolymorphicResolver;
    }

    @Override
    public void visitMissingClass(final Clazz referencingClass, final String missingClassName) {
      add(referencingClass, "class " + missingClassName);
    }

    @Override
    public void visitProgramDependency(final Clazz referencingClass, final Clazz dependencyClass) {
      // Cross-artifact library references are valid.
    }

    @Override
    public void visitAnyMissingMember(
        final Clazz referencingClass,
        final Clazz targetClass,
        final String memberName,
        final String memberDescriptor) {
      if (signaturePolymorphicResolver.recordIfSignaturePolymorphic(
          referencingClass, targetClass, memberName, memberDescriptor, unresolvedReferences)) {
        return;
      }
      add(
          referencingClass,
          "member " + targetClass.getName() + "." + memberName + memberDescriptor);
    }

    private void add(final Clazz referencingClass, final String missingReference) {
      unresolvedReferences
          .computeIfAbsent(referencingClass.getName(), unused -> new TreeSet<>())
          .add(referencingClass.getName() + " -> " + missingReference);
    }
  }

  /** Defers missing sibling links until a sibling class is reached. */
  private static final class RecordingLibraryReferenceVisitor implements InvalidReferenceVisitor {
    /** Maps each sibling class to its unresolved links. */
    private final Map<String, Set<String>> unresolvedReferences;

    /** Handles legal signature-polymorphic links omitted by Core's visitor. */
    private final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver;

    private RecordingLibraryReferenceVisitor(
        final Map<String, Set<String>> unresolvedReferences,
        final SignaturePolymorphicReferenceResolver signaturePolymorphicResolver) {
      this.unresolvedReferences = unresolvedReferences;
      this.signaturePolymorphicResolver = signaturePolymorphicResolver;
    }

    @Override
    public void visitMissingClass(final Clazz referencingClass, final String missingClassName) {
      add(referencingClass, "class " + missingClassName);
    }

    @Override
    public void visitProgramDependency(final Clazz referencingClass, final Clazz dependencyClass) {
      // Cross-artifact library references are valid.
    }

    @Override
    public void visitAnyMissingMember(
        final Clazz referencingClass,
        final Clazz targetClass,
        final String memberName,
        final String memberDescriptor) {
      if (signaturePolymorphicResolver.recordIfSignaturePolymorphic(
          referencingClass, targetClass, memberName, memberDescriptor, unresolvedReferences)) {
        return;
      }
      add(
          referencingClass,
          "member " + targetClass.getName() + "." + memberName + memberDescriptor);
    }

    private void add(final Clazz referencingClass, final String missingReference) {
      unresolvedReferences
          .computeIfAbsent(referencingClass.getName(), unused -> new TreeSet<>())
          .add(referencingClass.getName() + " -> " + missingReference);
    }
  }
}
