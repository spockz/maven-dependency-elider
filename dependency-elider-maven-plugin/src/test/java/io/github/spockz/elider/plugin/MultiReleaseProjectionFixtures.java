/* WHY: Builds compact multi-release and modular JARs used by projection behavior tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.test.CompilationFixtureSupport;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/** Creates compiler-backed archive fixtures for projection tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class MultiReleaseProjectionFixtures {
  /** Module descriptor entry removed from analysis projections. */
  private static final String MODULE_INFO_ENTRY = "module-info.class";

  /** Class entry used in the basic projection fixture. */
  private static final String API_ENTRY = "projection/Api.class";

  private MultiReleaseProjectionFixtures() {}

  static Path compileModularJar(final Path root) throws IOException {
    final Path sourceRoot = root.resolve("modular-src");
    final Path packageDirectory = sourceRoot.resolve("projection");
    final Path outputDirectory = root.resolve("modular-classes");
    Files.createDirectories(packageDirectory);
    Files.createDirectories(outputDirectory);
    final Path descriptor = sourceRoot.resolve("module-info.java");
    final Path api = packageDirectory.resolve("Api.java");
    Files.writeString(descriptor, "module projection.test { exports projection; }");
    Files.writeString(api, "package projection; public class Api {}");
    CompilationFixtureSupport.compile(outputDirectory, List.of(descriptor, api), "--release", "9");
    final Path jar = root.resolve("modular.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      addClass(output, outputDirectory.resolve(MODULE_INFO_ENTRY), MODULE_INFO_ENTRY);
      addClass(output, outputDirectory.resolve(API_ENTRY), API_ENTRY);
    }
    return jar;
  }

  static Path compile(final Path root, final String name, final int release, final String source)
      throws IOException {
    final Path sourceDirectory = root.resolve(name + "-src/projection");
    final Path outputDirectory = root.resolve(name + "-classes");
    Files.createDirectories(sourceDirectory);
    Files.createDirectories(outputDirectory);
    final Path sourceFile = sourceDirectory.resolve(sourceClassName(source));
    Files.writeString(sourceFile, source);
    CompilationFixtureSupport.compile(
        outputDirectory, List.of(sourceFile), "--release", Integer.toString(release));
    return outputDirectory
        .resolve("projection")
        .resolve(sourceClassName(source).replace(".java", ".class"));
  }

  static Path createMultiReleaseJar(final Path root, final Path... classes) throws IOException {
    final Path jar = root.resolve("projection.jar");
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
      addClass(output, classes[0], API_ENTRY);
      addClass(output, classes[1], "META-INF/versions/9/" + API_ENTRY);
      addClass(output, classes[2], "META-INF/versions/9/projection/NineOnly.class");
      addClass(output, classes[3], "META-INF/versions/21/" + API_ENTRY);
      addClass(output, classes[4], "META-INF/versions/21/projection/TwentyOneOnly.class");
    }
    return jar;
  }

  static void addClass(final JarOutputStream output, final Path classFile, final String entryName)
      throws IOException {
    output.putNextEntry(new JarEntry(entryName));
    Files.copy(classFile, output);
    output.closeEntry();
  }

  private static String sourceClassName(final String source) {
    final int classIndex = source.indexOf("class ") + "class ".length();
    final int nameEnd = source.indexOf(' ', classIndex);
    final int braceEnd = source.indexOf('{', classIndex);
    final int end = nameEnd < 0 ? braceEnd : Math.min(nameEnd, braceEnd);
    return source.substring(classIndex, end).trim() + ".java";
  }
}
