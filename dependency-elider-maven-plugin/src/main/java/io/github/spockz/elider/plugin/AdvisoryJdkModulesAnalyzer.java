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

/**
 * Advisory analysis of platform modules required by application bytecode and retained dependencies.
 * Emits recommendations suitable for jlink --add-modules.
 */
final class AdvisoryJdkModulesAnalyzer {
  static final String ADVISORY_MODULES_FILENAME = "dependency-elider-jdk-modules.txt";

  AdvisoryJdkModulesAnalyzer() {}

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

    final List<String> args = new ArrayList<>();
    args.add("--print-module-deps");
    args.add("--ignore-missing-deps");
    if (targetRelease >= 9) {
      args.add("--multi-release");
      args.add(String.valueOf(targetRelease));
    }
    if (!classPathEntries.isEmpty()) {
      final StringBuilder cp = new StringBuilder();
      for (final Path entry : classPathEntries) {
        if (!cp.isEmpty()) {
          cp.append(java.io.File.pathSeparator);
        }
        cp.append(entry.toAbsolutePath().normalize());
      }
      args.add("--class-path");
      args.add(cp.toString());
    }

    for (final Path input : inputPaths) {
      if (Files.exists(input)) {
        args.add(input.toAbsolutePath().normalize().toString());
      }
    }

    final StringWriter out = new StringWriter();
    final StringWriter err = new StringWriter();
    jdepsProvider
        .get()
        .run(new PrintWriter(out), new PrintWriter(err), args.toArray(String[]::new));

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

  static String formatModuleList(final Set<String> modules) {
    final StringBuilder sb = new StringBuilder();
    for (final String module : new TreeSet<>(modules)) {
      sb.append(module).append('\n');
    }
    return sb.toString();
  }
}
