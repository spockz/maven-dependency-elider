/* WHY: Consolidates test fixture Java compilation with standard flags and error handling. */

package io.github.spockz.elider.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/** Compiles test fixtures with standard compiler options. */
public final class CompilationFixtureSupport {
  private CompilationFixtureSupport() {}

  /** Compiles source files into target directory with standard flags. */
  public static void compile(
      final Path outputDirectory, final List<Path> sources, final String... extraArgs)
      throws IOException {
    Files.createDirectories(outputDirectory);
    final JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
    if (compiler == null) {
      throw new IllegalStateException("Test execution requires a JDK compiler");
    }
    final List<String> arguments = new ArrayList<>();
    arguments.addAll(List.of("--release", "21", "-proc:none", "-d", outputDirectory.toString()));
    arguments.addAll(List.of(extraArgs));
    sources.forEach(source -> arguments.add(source.toString()));
    final int result = compiler.run(null, null, null, arguments.toArray(String[]::new));
    if (result != 0) {
      throw new IOException(
          "Compilation failed with exit code " + result + " for sources: " + sources);
    }
  }
}
