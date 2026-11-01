// WHY: Extracts source declarations and routine owners only after javac analysis resolves them.

package io.github.spockz.elider.correspondence;

import com.sun.source.tree.ClassTree;
import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.tree.MethodTree;
import com.sun.source.tree.Tree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.TreePath;
import com.sun.source.util.TreePathScanner;
import com.sun.source.util.Trees;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import javax.lang.model.element.Element;
import javax.lang.model.element.ExecutableElement;
import javax.lang.model.element.TypeElement;

/** Captures declarations from one analyzed Java source unit. */
final class SourceUnitAstInspector {
  private SourceUnitAstInspector() {}

  /* default */ static Inspection inspect(final CompilationUnitTree unit, final JavacTask task)
      throws IOException {
    return new Inspection(topLevelTypes(unit, task), routineDeclarations(unit, task));
  }

  private static Set<String> topLevelTypes(final CompilationUnitTree unit, final JavacTask task)
      throws IOException {
    final Trees trees = Trees.instance(task);
    final Set<String> names = new TreeSet<>();
    for (final Tree declaration : unit.getTypeDecls()) {
      if (declaration instanceof ClassTree) {
        final Element element = trees.getElement(TreePath.getPath(unit, declaration));
        if (!(element instanceof TypeElement type)) {
          throw new IOException("Could not resolve top-level source declaration");
        }
        names.add(binaryName(task, type));
      }
    }
    return Set.copyOf(names);
  }

  private static List<SourceReproductionResult.RoutineDeclaration> routineDeclarations(
      final CompilationUnitTree unit, final JavacTask task) throws IOException {
    final Trees trees = Trees.instance(task);
    final List<SourceReproductionResult.RoutineDeclaration> declarations = new ArrayList<>();
    final String[] unresolved = new String[1];
    new TreePathScanner<Void, Void>() {
      @Override
      public Void visitMethod(final MethodTree method, final Void unused) {
        appendRoutine(method, getCurrentPath(), trees, task, declarations, unresolved);
        return unresolved[0] == null ? super.visitMethod(method, unused) : null;
      }
    }.scan(unit, null);
    if (unresolved[0] != null) {
      throw new IOException(unresolved[0]);
    }
    return List.copyOf(declarations);
  }

  @SuppressWarnings("PMD.LawOfDemeter") // The Javac tree API resolves each routine owner.
  private static void appendRoutine(
      final MethodTree method,
      final TreePath methodPath,
      final Trees trees,
      final JavacTask task,
      final List<SourceReproductionResult.RoutineDeclaration> declarations,
      final String... unresolved) {
    final Element element = trees.getElement(methodPath);
    if (!(element instanceof ExecutableElement executable)
        || !(executable.getEnclosingElement() instanceof TypeElement owner)) {
      unresolved[0] = "Could not resolve a Java routine owner";
      return;
    }
    declarations.add(
        new SourceReproductionResult.RoutineDeclaration(
            method.getName().toString(), binaryName(task, owner)));
  }

  @SuppressWarnings("PMD.LawOfDemeter") // Javac Elements supplies the binary name for a type.
  private static String binaryName(final JavacTask task, final TypeElement type) {
    return task.getElements().getBinaryName(type).toString();
  }

  /* default */ record Inspection(
      Set<String> topLevelTypes, List<SourceReproductionResult.RoutineDeclaration> routines) {
    Inspection {
      topLevelTypes = Set.copyOf(topLevelTypes);
      routines = List.copyOf(routines);
    }
  }
}
