// WHY: Builds exact source and binary JAR pairs for public core reproduction tests.

package io.github.spockz.elider.correspondence;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import javax.tools.ToolProvider;

/** Builds real JAR fixtures with the pinned JDK compiler. */
final class SourceReproductionTestArchives {
  private SourceReproductionTestArchives() {}

  /* default */ static Archives write(
      final Path directory,
      final String sourceEntry,
      final String source,
      final boolean manifestClassPath,
      final Optional<AdditionalSource> additionalSource,
      final boolean extraClass)
      throws IOException {
    Files.createDirectories(directory);
    final Path sourceRoot = Files.createDirectories(directory.resolve("sources"));
    final List<Path> sourceFiles = new ArrayList<>();
    sourceFiles.add(writeSource(sourceRoot, sourceEntry, source));
    if (additionalSource.isPresent()) {
      final AdditionalSource additional = additionalSource.orElseThrow();
      sourceFiles.add(writeSource(sourceRoot, additional.entry(), additional.source()));
    }
    final Path classes = Files.createDirectories(directory.resolve("classes"));
    compileSources(sourceFiles, classes);
    final Path sourcesJar = directory.resolve("demo-1.0-sources.jar");
    final Path originalJar = directory.resolve("demo-1.0.jar");
    writeSourcesJar(sourcesJar, sourceFiles, sourceRoot);
    writeOriginalJar(originalJar, classes, manifestClassPath, extraClass);
    return new Archives(originalJar, sourcesJar);
  }

  private static Path writeSource(final Path root, final String entry, final String source)
      throws IOException {
    final Path path = root.resolve(entry).normalize();
    Files.createDirectories(path.getParent());
    Files.writeString(path, source, StandardCharsets.UTF_8);
    return path;
  }

  private static void compileSources(final List<Path> sources, final Path classes)
      throws IOException {
    final List<String> arguments =
        new ArrayList<>(
            List.of(
                "--release",
                "21",
                "-encoding",
                "UTF-8",
                "-proc:none",
                "-implicit:none",
                "-d",
                classes.toString()));
    sources.stream().map(Path::toString).forEach(arguments::add);
    if (ToolProvider.getSystemJavaCompiler().run(null, null, null, arguments.toArray(String[]::new))
        != 0) {
      throw new IOException("Could not compile source reproduction fixture");
    }
  }

  private static void writeSourcesJar(
      final Path jar, final List<Path> sourceFiles, final Path sourceRoot) throws IOException {
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      for (final Path source : sourceFiles) {
        writePathEntry(output, sourceRoot.relativize(source).toString().replace('\\', '/'), source);
      }
    }
  }

  private static void writeOriginalJar(
      final Path jar, final Path classes, final boolean manifestClassPath, final boolean extraClass)
      throws IOException {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    if (manifestClassPath) {
      manifest.getMainAttributes().put(Attributes.Name.CLASS_PATH, "helper.jar");
    }
    try (JarOutputStream output =
            manifestClassPath
                ? new JarOutputStream(Files.newOutputStream(jar), manifest)
                : new JarOutputStream(Files.newOutputStream(jar));
        Stream<Path> paths = Files.walk(classes)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).sorted().toList()) {
        writePathEntry(
            output, classes.relativize(classFile).toString().replace('\\', '/'), classFile);
      }
      if (extraClass) {
        output.putNextEntry(new JarEntry("org/example/Extra.class"));
        output.write(new byte[] {1, 2, 3});
        output.closeEntry();
      }
    }
  }

  private static void writePathEntry(
      final JarOutputStream output, final String name, final Path content) throws IOException {
    output.putNextEntry(new JarEntry(name));
    Files.copy(content, output);
    output.closeEntry();
  }

  /* default */ record Archives(Path originalJar, Path sourcesJar) {}

  /* default */ record AdditionalSource(String entry, String source) {}
}
