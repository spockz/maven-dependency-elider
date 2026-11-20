// WHY: Analyzes application classes and retained dependencies with target-aware jdeps to suggest
// platform modules for jlink.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.spi.ToolProvider;

/** Advisory analysis of platform modules required by application bytecode. */
@SuppressWarnings({
  "PMD.CommentRequired",
  "PMD.CommentDefaultAccessModifier",
  "PMD.CommentSize",
  "PMD.CognitiveComplexity",
  "PMD.CyclomaticComplexity",
  "PMD.NPathComplexity",
  "PMD.AtLeastOneConstructor"
})
final class AdvisoryJdkModulesAnalyzer {
  static final String ADVISORY_MODULES_FILENAME = "dependency-elider-jdk-modules.txt";
  private static final int FIRST_MODULAR_RELEASE = 9;

  /**
   * Analyzes the given input paths (e.g. application classes directory, retained jars) with jdeps
   * using target release and classpath.
   */
  Set<String> analyze(
      final List<Path> inputPaths, final List<Path> classPathEntries, final int targetRelease)
      throws IOException {
    final Optional<ToolProvider> jdepsProvider = ToolProvider.findFirst("jdeps");
    if (jdepsProvider.isEmpty()) {
      return Set.of("java.base");
    }
    return analyze(inputPaths, classPathEntries, targetRelease, jdepsProvider.get());
  }

  /* default */ Set<String> analyze(
      final List<Path> inputPaths,
      final List<Path> classPathEntries,
      final int targetRelease,
      final ToolProvider jdeps)
      throws IOException {
    return analyzeWithTool(inputPaths, classPathEntries, targetRelease, jdeps, null);
  }

  /** Uses the selected installed image and reports any tool failure to the advisory caller. */
  /* package */ Set<String> analyzeForRuntime(
      final List<Path> inputs, final List<Path> classPath, final int release, final Path runtime)
      throws IOException {
    final ToolProvider tool =
        ToolProvider.findFirst("jdeps").orElseThrow(() -> new IOException("jdeps is unavailable"));
    return analyzeWithTool(inputs, classPath, release, tool, runtime);
  }

  private Set<String> analyzeWithTool(
      final List<Path> inputPaths,
      final List<Path> classPathEntries,
      final int targetRelease,
      final ToolProvider jdeps,
      final Path runtime)
      throws IOException {
    final List<String> existingInputs = new ArrayList<>();
    for (final Path input : inputPaths) {
      if (Files.exists(input)) {
        existingInputs.add(input.toAbsolutePath().normalize().toString());
      }
    }
    if (existingInputs.isEmpty()) {
      return Set.of("java.base");
    }

    final List<String> args = new ArrayList<>();
    args.add("--print-module-deps");
    args.add("--ignore-missing-deps");
    args.add("--multi-release");
    args.add(targetRelease >= FIRST_MODULAR_RELEASE ? String.valueOf(targetRelease) : "base");
    if (runtime != null) {
      args.add("--system");
      args.add(runtime.toString());
    }
    if (!classPathEntries.isEmpty()) {
      final StringBuilder classpath = new StringBuilder();
      for (final Path entry : classPathEntries) {
        if (!classpath.isEmpty()) {
          classpath.append(java.io.File.pathSeparator);
        }
        classpath.append(entry.toAbsolutePath().normalize());
      }
      args.add("--class-path");
      args.add(classpath.toString());
    }
    args.addAll(existingInputs);

    final StringWriter out = new StringWriter();
    final StringWriter err = new StringWriter();
    final int exitCode = run(jdeps, args, out, err);
    if (exitCode != 0) {
      final String errorText = err.toString().trim();
      final String outputText = out.toString().trim();
      final String details = errorText.isEmpty() ? outputText : errorText;
      throw new IOException(
          details.isEmpty()
              ? "jdeps failed with exit code " + exitCode
              : "jdeps failed with exit code " + exitCode + ": " + details);
    }

    final Set<String> modules = new TreeSet<>();
    final String result = out.toString().trim();
    if (!result.isEmpty()) {
      for (final String mod : result.split("[,\\s]+")) {
        final String trimmed = mod.trim();
        if (!trimmed.isEmpty()
            && !trimmed.startsWith("Error:")
            && !trimmed.startsWith("Warning:")) {
          modules.add(trimmed);
        }
      }
    }
    if (modules.isEmpty()) {
      modules.add("java.base");
    }
    return modules;
  }

  @SuppressWarnings(
      "PMD.AvoidCatchingGenericException") // Tool adapters can throw unchecked failures.
  private static int run(
      final ToolProvider tool,
      final List<String> args,
      final StringWriter out,
      final StringWriter err)
      throws IOException {
    try {
      return tool.run(new PrintWriter(out), new PrintWriter(err), args.toArray(String[]::new));
    } catch (final RuntimeException failure) {
      throw new IOException("jdeps failed: " + failure.getMessage(), failure);
    }
  }

  static String formatModuleList(final Set<String> modules) {
    final StringBuilder output = new StringBuilder();
    for (final String module : new TreeSet<>(modules)) {
      output.append(module).append('\n');
    }
    return output.toString();
  }
}
