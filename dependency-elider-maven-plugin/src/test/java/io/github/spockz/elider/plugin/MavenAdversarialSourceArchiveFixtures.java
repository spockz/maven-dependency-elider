// WHY: Builds narrow malformed source and trim archives for path-identity proof regressions.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import javax.tools.ToolProvider;

/** Creates exact compiled archives with adversarial source path associations. */
final class MavenAdversarialSourceArchiveFixtures {
  private MavenAdversarialSourceArchiveFixtures() {}

  /* default */ static MavenSourceCorrespondenceTestArtifacts.Archives writePackagePathSwap(
      final Path directory) throws IOException {
    final Path sourceRoot = Files.createDirectories(directory.resolve("package-swap-sources"));
    final Path claimedPath = sourceRoot.resolve("org/example/Outer.java");
    final Path alternatePath = sourceRoot.resolve("alternate/org/other/Outer.java");
    Files.createDirectories(claimedPath.getParent());
    Files.createDirectories(alternatePath.getParent());
    Files.writeString(claimedPath, "package org.other; class Other {}");
    Files.writeString(alternatePath, "package org.example; class Outer {}");
    final Path classes = Files.createDirectories(directory.resolve("package-swap-classes"));
    final int exitCode =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-encoding",
                "UTF-8",
                "-proc:none",
                "-implicit:none",
                "-d",
                classes.toString(),
                claimedPath.toString(),
                alternatePath.toString());
    if (exitCode != 0) {
      throw new IOException("Could not compile the swapped source-path fixture");
    }
    final Path sourcesJar = directory.resolve("demo-1.0-sources.jar");
    final Path originalJar = directory.resolve("demo-1.0.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(sourcesJar))) {
      addEntry(output, "org/example/Outer.java", Files.readAllBytes(claimedPath));
      addEntry(output, "alternate/org/other/Outer.java", Files.readAllBytes(alternatePath));
    }
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(originalJar));
        Stream<Path> paths = Files.walk(classes)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).sorted().toList()) {
        addEntry(
            output,
            classes.relativize(classFile).toString().replace('\\', '/'),
            Files.readAllBytes(classFile));
      }
    }
    return new MavenSourceCorrespondenceTestArtifacts.Archives(originalJar, sourcesJar);
  }

  /* default */ static Path copyJarKeepingEntry(
      final Path original, final Path trimmed, final String retainedEntry) throws IOException {
    try (JarFile input = new JarFile(original.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(trimmed))) {
      final JarEntry entry = input.getJarEntry(retainedEntry);
      if (entry == null) {
        throw new IOException("Required source-output fixture entry is missing: " + retainedEntry);
      }
      output.putNextEntry(new JarEntry(entry.getName()));
      try (InputStream content = input.getInputStream(entry)) {
        content.transferTo(output);
      }
      output.closeEntry();
    }
    return trimmed;
  }

  private static void addEntry(final JarOutputStream output, final String name, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }
}
