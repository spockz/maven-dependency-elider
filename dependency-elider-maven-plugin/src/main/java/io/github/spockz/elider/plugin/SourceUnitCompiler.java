// WHY: Isolates every exact Java source unit and records every emitted class family.

package io.github.spockz.elider.plugin;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Reproduces all Java sources as independent JDK21 compilation tasks. */
final class SourceUnitCompiler {
  /** Required compiler feature release for the pinned JDK image. */
  private static final int JAVA_FEATURE_VERSION = 21;

  /** Exactly one explicit compilation unit is accepted per task. */
  private static final int ONE_SOURCE_UNIT = 1;

  private SourceUnitCompiler() {}

  /* default */ static Compilation compile(
      final SourceCorrespondenceArchive sources,
      final Path originalJar,
      final String compilerIdentity)
      throws IOException {
    final JavaCompiler compiler = requireCompiler();
    try (SourceCompilationWorkspace workspace = SourceCompilationWorkspace.create()) {
      final Path extractedSources = workspace.directory("sources");
      writeSources(sources, extractedSources);
      final Path emptySourcePath = workspace.directory("empty-source-path");
      final Path outputs = workspace.directory("outputs");
      final List<SourceBuildCorrespondence.SourceUnit> sourceUnits =
          compileUnits(sources, originalJar, compiler, extractedSources, emptySourcePath, outputs);
      if (compilerIdentity == null || compilerIdentity.isBlank()) {
        throw new IOException("Pinned JDK compiler identity is unavailable");
      }
      return new Compilation(compilerIdentity, fixedOptions(), sourceUnits);
    }
  }

  private static JavaCompiler requireCompiler() throws IOException {
    if (Runtime.version().feature() != JAVA_FEATURE_VERSION) {
      throw new IOException("Source reproduction supports only JDK 21");
    }
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IOException("JDK 21 javac is unavailable");
    }
    return compiler;
  }

  private static void writeSources(
      final SourceCorrespondenceArchive sources, final Path extractedRoot) throws IOException {
    for (final String entry : sources.sourceEntries()) {
      final Path source = extractedRoot.resolve(entry).normalize();
      if (!source.startsWith(extractedRoot)) {
        throw new IOException("Source archive path escapes its isolated directory: " + entry);
      }
      final Path parent = source.getParent();
      if (parent == null) {
        throw new IOException("Source archive entry has no parent directory: " + entry);
      }
      Files.createDirectories(parent);
      Files.write(source, sources.sourceContent(entry));
    }
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // This map is thread-confined to one compilation.
  private static List<SourceBuildCorrespondence.SourceUnit> compileUnits(
      final SourceCorrespondenceArchive sources,
      final Path originalJar,
      final JavaCompiler compiler,
      final Path extractedRoot,
      final Path emptySourcePath,
      final Path outputs)
      throws IOException {
    final List<SourceBuildCorrespondence.SourceUnit> units = new ArrayList<>();
    final Map<String, SourceBuildCorrespondence.ClassEntry> emittedPaths = new HashMap<>();
    int emittedClassCount = 0;
    long emittedClassBytes = 0;
    int index = 0;
    for (final String sourceEntry : sources.sourceEntries()) {
      final Path unitOutput = Files.createDirectory(outputs.resolve("unit-" + index));
      index++;
      final UnitCompilation compiled =
          compileOne(
              extractedRoot.resolve(sourceEntry),
              originalJar,
              emptySourcePath,
              unitOutput,
              compiler);
      final SourceClassOutputInventory.Inventory outputInventory =
          SourceClassOutputInventory.read(unitOutput);
      final List<SourceBuildCorrespondence.ClassEntry> classes = outputInventory.classes();
      emittedClassCount += classes.size();
      emittedClassBytes += outputInventory.totalBytes();
      SourceClassOutputInventory.requireAggregateBounds(emittedClassCount, emittedClassBytes);
      if (classes.isEmpty() && !compiled.topLevelTypes().isEmpty()) {
        throw new IOException("Source unit emitted no classes: " + sourceEntry);
      }
      for (final SourceBuildCorrespondence.ClassEntry emitted : classes) {
        if (emittedPaths.putIfAbsent(emitted.path(), emitted) != null) {
          throw new IOException("Two source units emitted the same class entry: " + emitted.path());
        }
      }
      units.add(
          new SourceBuildCorrespondence.SourceUnit(
              sourceEntry,
              sha256(sources.sourceContent(sourceEntry)),
              compiled.topLevelTypes(),
              compiled.routines(),
              classes));
    }
    return List.copyOf(units);
  }

  private static UnitCompilation compileOne(
      final Path source,
      final Path originalJar,
      final Path emptySourcePath,
      final Path output,
      final JavaCompiler compiler)
      throws IOException {
    final DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager fileManager =
        compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      final List<JavaFileObject> sourceUnits = sourceUnits(fileManager, source);
      final List<String> options = compilerOptions(originalJar, emptySourcePath, output);
      final JavacTask task =
          (JavacTask) compiler.getTask(null, fileManager, diagnostics, options, null, sourceUnits);
      final List<CompilationUnitTree> parsed = new ArrayList<>();
      final Iterable<? extends CompilationUnitTree> parsedUnits = task.parse();
      for (final CompilationUnitTree parsedUnit : parsedUnits) {
        parsed.add(parsedUnit);
      }
      if (parsed.size() != ONE_SOURCE_UNIT) {
        throw new IOException("Compiler did not parse exactly one source unit: " + source);
      }
      task.analyze();
      requireNoErrors(diagnostics, source);
      final CompilationUnitTree unit = parsed.getFirst();
      final SourceUnitAstInspector.Inspection inspection =
          SourceUnitAstInspector.inspect(unit, task);
      task.generate();
      requireNoErrors(diagnostics, source);
      return new UnitCompilation(inspection.topLevelTypes(), inspection.routines());
    } catch (final ClassCastException exception) {
      throw new IOException("The configured compiler is not supported javac", exception);
    }
  }

  private static List<JavaFileObject> sourceUnits(
      final StandardJavaFileManager fileManager, final Path source) throws IOException {
    final List<JavaFileObject> units =
        java.util.stream.StreamSupport.stream(
                fileManager.getJavaFileObjects(source.toFile()).spliterator(), false)
            .map(JavaFileObject.class::cast)
            .toList();
    if (units.size() != ONE_SOURCE_UNIT) {
      throw new IOException("Expected one explicit source unit: " + source);
    }
    return units;
  }

  private static List<String> compilerOptions(
      final Path originalJar, final Path emptySourcePath, final Path output) {
    return List.of(
        "--release",
        "21",
        "-encoding",
        "UTF-8",
        "-proc:none",
        "-implicit:none",
        "-sourcepath",
        emptySourcePath.toString(),
        "-classpath",
        originalJar.toString(),
        "-d",
        output.toString());
  }

  private static void requireNoErrors(
      final DiagnosticCollector<JavaFileObject> diagnostics, final Path source) throws IOException {
    final List<String> errors =
        diagnostics.getDiagnostics().stream()
            .filter(value -> value.getKind() == Diagnostic.Kind.ERROR)
            .map(value -> value.getLineNumber() + ":" + value.getMessage(null))
            .toList();
    if (!errors.isEmpty()) {
      throw new IOException(
          "Cannot reproduce source unit " + source + ": " + String.join("; ", errors));
    }
  }

  private static List<String> fixedOptions() {
    return List.of(
        "--release=21",
        "-encoding=UTF-8",
        "-proc:none",
        "-implicit:none",
        "-sourcepath=<empty>",
        "-classpath=<exact-original-jar>");
  }

  private static String sha256(final byte[] bytes) {
    try {
      return java.util.HexFormat.of()
          .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (final java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private record UnitCompilation(
      Set<String> topLevelTypes, List<SourceBuildCorrespondence.RoutineDeclaration> routines) {}

  /* default */ record Compilation(
      String compilerIdentity,
      List<String> options,
      List<SourceBuildCorrespondence.SourceUnit> units) {
    Compilation {
      options = List.copyOf(options);
      units = List.copyOf(units);
    }
  }
}
