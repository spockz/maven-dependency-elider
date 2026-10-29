/* WHY: Consolidates in-memory and file-based test fixture Java compilation with standard flags. */

package io.github.spockz.elider.test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/** Compiles test fixtures with standard options and optional archive packing. */
@SuppressWarnings({"PMD.AvoidInstantiatingObjectsInLoops"})
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

  /** Compiles source text entries into a JAR archive with standard flags. */
  public static Path compileToJar(
      final Path jarFile,
      final Path sourceDirectory,
      final Map<String, String> sources,
      final Path classpath)
      throws IOException {
    final Path parent = jarFile.getParent();
    if (parent == null) {
      throw new IOException("JAR file has no parent directory: " + jarFile);
    }
    final Path classesDir = parent.resolve(jarFile.getFileName().toString() + "-classes");
    Files.createDirectories(sourceDirectory);
    Files.createDirectories(classesDir);
    final List<Path> sourceFiles = new ArrayList<>();
    for (final Map.Entry<String, String> entry : sources.entrySet()) {
      final Path sourcePath = sourceDirectory.resolve(entry.getKey());
      final Path sourceParent = sourcePath.getParent();
      if (sourceParent != null) {
        Files.createDirectories(sourceParent);
      }
      Files.writeString(sourcePath, entry.getValue());
      sourceFiles.add(sourcePath);
    }
    final List<String> extraArgs = new ArrayList<>();
    if (classpath != null) {
      extraArgs.addAll(List.of("-classpath", classpath.toString()));
    }
    compile(classesDir, sourceFiles, extraArgs.toArray(String[]::new));
    Files.createDirectories(parent);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jarFile));
        Stream<Path> paths = Files.walk(classesDir)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).toList()) {
        final String entryName = classesDir.relativize(classFile).toString().replace('\\', '/');
        output.putNextEntry(new JarEntry(entryName));
        Files.copy(classFile, output);
        output.closeEntry();
      }
    }
    return jarFile;
  }
}
