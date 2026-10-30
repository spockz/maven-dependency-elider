/* WHY: Inventories source-declared classes without depending on pruning's reference scanner. */

package io.github.spockz.elider.plugin;

import com.sun.source.tree.AssertTree;
import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.SwitchExpressionTree;
import com.sun.source.tree.SwitchTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePathScanner;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Parses Java sources to find declared binary class names. */
@SuppressWarnings({
  "PMD.CommentDefaultAccessModifier",
  "PMD.LawOfDemeter",
  "PMD.UseConcurrentHashMap"
})
final class MavenSourceDeclarationScanner {
  private MavenSourceDeclarationScanner() {}

  static Map<Path, Set<String>> scan(final List<Path> sources) throws IOException {
    if (sources.isEmpty()) {
      return Map.of();
    }
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IOException("A JDK compiler is required to inventory Maven Java sources");
    }
    return parseSources(compiler, sources);
  }

  private static Map<Path, Set<String>> parseSources(
      final JavaCompiler compiler, final List<Path> sources) throws IOException {
    final DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(diagnostics, null, null)) {
      final Iterable<? extends JavaFileObject> units =
          fileManager.getJavaFileObjectsFromPaths(sources);
      final JavacTask task =
          (JavacTask)
              compiler.getTask(null, fileManager, diagnostics, List.of("-proc:none"), null, units);
      final List<CompilationUnitTree> parsed = new ArrayList<>();
      task.parse().forEach(parsed::add);
      failOnDiagnostics(diagnostics);
      final Map<Path, Set<String>> declarations = new HashMap<>();
      for (final CompilationUnitTree unit : parsed) {
        final Path source = Path.of(unit.getSourceFile().toUri()).toRealPath();
        declarations.put(source, declaredTypes(unit));
      }
      return Map.copyOf(declarations);
    }
  }

  private static void failOnDiagnostics(final DiagnosticCollector<JavaFileObject> diagnostics)
      throws IOException {
    final List<String> errors =
        diagnostics.getDiagnostics().stream()
            .filter(diagnostic -> diagnostic.getKind() == Diagnostic.Kind.ERROR)
            .map(diagnostic -> diagnostic.getSource() + ":" + diagnostic.getLineNumber())
            .toList();
    if (!errors.isEmpty()) {
      throw new IOException(
          "Cannot inventory Maven Java declarations: " + String.join("; ", errors));
    }
  }

  private static Set<String> declaredTypes(final CompilationUnitTree unit) throws IOException {
    final String packageName =
        unit.getPackageName() == null ? "" : unit.getPackageName().toString();
    final String prefix = packageName.isEmpty() ? "" : packageName + ".";
    final Set<String> names = new TreeSet<>();
    try {
      new DeclarationScanner(prefix, names).scan(unit, "");
    } catch (final InvalidSourceDeclaration failure) {
      throw new IOException(
          "Unsupported Java source declaration: " + failure.getMessage(), failure);
    }
    return Set.copyOf(names);
  }

  /** Visits member types and refuses names that need compiler-generated numbering. */
  private static final class DeclarationScanner extends TreePathScanner<Void, String> {
    /** Package prefix used when the visitor enters a top-level declaration. */
    private final String packagePrefix;

    /** Mutable declaration set local to this single-threaded source parse. */
    private final Set<String> discoveredNames;

    /** Tracks whether assertions can trigger an interface-generated helper class. */
    private boolean currentTypeIsInterface;

    DeclarationScanner(final String packagePrefix, final Set<String> discoveredNames) {
      super();
      this.packagePrefix = packagePrefix;
      this.discoveredNames = discoveredNames;
    }

    @Override
    public Void visitClass(final ClassTree tree, final String owner) {
      final String name = tree.getSimpleName().toString();
      if (name.isBlank()) {
        throw new InvalidSourceDeclaration("anonymous classes have compiler-assigned names");
      }
      final Tree parent = getCurrentPath().getParentPath().getLeaf();
      if (!(parent instanceof CompilationUnitTree || parent instanceof ClassTree)) {
        throw new InvalidSourceDeclaration("local classes have compiler-assigned names: " + name);
      }
      final String binaryName = owner.isEmpty() ? packagePrefix + name : owner + "$" + name;
      if (!binaryName.matches("[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
        throw new InvalidSourceDeclaration(binaryName);
      }
      discoveredNames.add(binaryName);
      final boolean enclosingInterface = currentTypeIsInterface;
      currentTypeIsInterface = tree.getKind() == Tree.Kind.INTERFACE;
      try {
        return super.visitClass(tree, binaryName);
      } finally {
        currentTypeIsInterface = enclosingInterface;
      }
    }

    @Override
    public Void visitAssert(final AssertTree tree, final String owner) {
      if (currentTypeIsInterface) {
        throw new InvalidSourceDeclaration(
            "assertions in interfaces can create compiler-generated class providers");
      }
      return super.visitAssert(tree, owner);
    }

    @Override
    public Void visitSwitch(final SwitchTree tree, final String owner) {
      throw new InvalidSourceDeclaration(
          "switch statements may create compiler-generated class providers");
    }

    @Override
    public Void visitSwitchExpression(final SwitchExpressionTree tree, final String owner) {
      throw new InvalidSourceDeclaration(
          "switch expressions may create compiler-generated class providers");
    }
  }

  /** Signals source forms whose binary names cannot be derived from syntax alone. */
  private static final class InvalidSourceDeclaration extends RuntimeException {
    private static final long serialVersionUID = 1L;

    InvalidSourceDeclaration(final String name) {
      super(name);
    }
  }
}
