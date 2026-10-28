// WHY: Resolve source symbols so pruning preserves compile-time owners absent from runtime
// evidence.

package io.github.spockz.elider.plugin;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.IdentifierTree;
import com.sun.source.tree.MemberSelectTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.lang.model.element.Element;
import javax.lang.model.element.TypeElement;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Resolves source symbols using javac and the Maven compile classpath. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter",
  "PMD.CommentRequired"
})
final class JavaSourceReferenceScanner {
  record SourceScan(Set<String> referencedTypes, Set<String> declaredTypes) {}

  /** Resolves source symbols and fails when javac cannot complete attribution. */
  Set<String> scan(
      final Collection<String> sourceRoots,
      final Collection<String> classpath,
      final List<String> compilerOptions)
      throws IOException {
    return scanFiles(sourceFiles(sourceRoots), classpath, compilerOptions);
  }

  Set<String> scanFiles(
      final List<Path> sources,
      final Collection<String> classpath,
      final List<String> compilerOptions)
      throws IOException {
    return scanFilesDetailed(sources, classpath, compilerOptions).referencedTypes();
  }

  SourceScan scanFilesDetailed(
      final List<Path> sources,
      final Collection<String> classpath,
      final List<String> compilerOptions)
      throws IOException {
    if (sources.isEmpty()) {
      return new SourceScan(Set.of(), Set.of());
    }
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IOException("A JDK compiler is required to resolve production source references");
    }
    final DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(diagnostics, null, null)) {
      final Iterable<? extends JavaFileObject> units =
          fileManager.getJavaFileObjectsFromPaths(sources);
      final List<String> options = new ArrayList<>(List.of("-proc:none"));
      if (!classpath.isEmpty()) {
        options.add("-classpath");
        options.add(String.join(java.io.File.pathSeparator, classpath));
      }
      options.addAll(compilerOptions);
      final JavacTask task =
          (JavacTask) compiler.getTask(null, fileManager, diagnostics, options, null, units);
      final List<com.sun.source.tree.CompilationUnitTree> parsed = new ArrayList<>();
      task.parse().forEach(parsed::add);
      task.analyze();
      final List<String> errors =
          diagnostics.getDiagnostics().stream()
              .filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
              .map(JavaSourceReferenceScanner::formatDiagnostic)
              .toList();
      if (!errors.isEmpty()) {
        throw new IOException(
            "Cannot resolve production source references: " + String.join("; ", errors));
      }
      final Trees trees = Trees.instance(task);
      final Set<String> references = new TreeSet<>();
      final Set<String> declarations = new TreeSet<>();
      final ReferenceVisitor visitor = new ReferenceVisitor(trees, task, declarations);
      for (final com.sun.source.tree.CompilationUnitTree unit : parsed) {
        visitor.scan(unit, references);
      }
      return new SourceScan(Set.copyOf(references), Set.copyOf(declarations));
    }
  }

  static List<Path> sourceFiles(final Collection<String> sourceRoots) throws IOException {
    final List<Path> sources = new ArrayList<>();
    for (final String root : sourceRoots) {
      final Path rootPath = Path.of(root);
      if (Files.isDirectory(rootPath)) {
        try (java.util.stream.Stream<Path> paths = Files.walk(rootPath)) {
          sources.addAll(
              paths
                  .filter(path -> Files.isRegularFile(path) && path.toString().endsWith(".java"))
                  .toList());
        }
      }
    }
    return sources;
  }

  private static String formatDiagnostic(final Diagnostic<? extends JavaFileObject> diagnostic) {
    return diagnostic.getSource()
        + ":"
        + diagnostic.getLineNumber()
        + ": "
        + diagnostic.getMessage(null);
  }

  private static final class ReferenceVisitor extends TreePathScanner<Void, Set<String>> {
    private final Trees trees;
    private final javax.lang.model.util.Elements elements;
    private final Set<String> declarations;

    ReferenceVisitor(final Trees trees, final JavacTask task, final Set<String> declarations) {
      super();
      this.trees = trees;
      this.elements = task.getElements();
      this.declarations = declarations;
    }

    @Override
    public Void visitClass(final ClassTree tree, final Set<String> references) {
      final Element element = trees.getElement(getCurrentPath());
      if (element instanceof TypeElement type) {
        declarations.add(elements.getBinaryName(type).toString());
      }
      return super.visitClass(tree, references);
    }

    @Override
    public Void visitIdentifier(final IdentifierTree tree, final Set<String> references) {
      addReference(getCurrentPath(), references);
      return super.visitIdentifier(tree, references);
    }

    @Override
    public Void visitMemberSelect(final MemberSelectTree tree, final Set<String> references) {
      addReference(getCurrentPath(), references);
      return super.visitMemberSelect(tree, references);
    }

    private void addReference(final TreePath path, final Set<String> references) {
      final Element element = trees.getElement(path);
      if (element instanceof TypeElement type) {
        references.add(elements.getBinaryName(type).toString());
      } else if (element != null && element.getEnclosingElement() instanceof TypeElement owner) {
        references.add(elements.getBinaryName(owner).toString());
      }
    }
  }
}
