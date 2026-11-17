// WHY: Compiles immutable closure fixture classes, JARs, and Seed.class once per JVM fork.

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.test.CompilationFixtureSupport;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

/** Caches compiled fixture bytecode and JAR archives across closure tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
final class ClosureFixtureCompileCache {
  /** Directory name holding compiled fixture classes. */
  private static final String CLASSES_DIRECTORY = "classes";

  /** Resource entry added to closure fixture JARs. */
  private static final String FIXTURE_RESOURCE = "data/fixture.txt";

  /** Resource content added to closure fixture JARs. */
  private static final String FIXTURE_RESOURCE_CONTENT = "preserve this resource\n";

  /** Shared duplicate-owner class entry path. */
  private static final String EXTRA_CLASS_ENTRY = "closure/a/Extra.class";

  /** Graph-ancestor class entry path. */
  private static final String ANCESTOR_CLASS_ENTRY = "closure/d/Ancestor.class";

  /** Cached compiled bytes for {@code fixture.Seed}. */
  private static final AtomicReference<byte[]> SEED_CLASS_BYTES = new AtomicReference<>();

  /** Cached compiled closure class files and JAR archives keyed by fixture options. */
  private static final Map<FixtureKey, CachedFixtureFiles> CLOSURE_CACHE =
      new ConcurrentHashMap<>();

  private ClosureFixtureCompileCache() {}

  static byte[] seedClassBytes() throws IOException {
    final byte[] cached = SEED_CLASS_BYTES.get();
    if (cached != null) {
      return cached;
    }
    final Path tempRoot = Files.createTempDirectory("elider-seed-cache");
    try {
      final Path sourceRoot = Files.createDirectories(tempRoot.resolve("complete-source"));
      final Path output = Files.createDirectories(tempRoot.resolve(CLASSES_DIRECTORY));
      final Path seed = sourceRoot.resolve("fixture/Seed.java");
      Files.createDirectories(seed.getParent());
      Files.writeString(seed, "package fixture; public class Seed {}\n");
      CompilationFixtureSupport.compile(output, List.of(seed));
      SEED_CLASS_BYTES.compareAndSet(
          null, Files.readAllBytes(output.resolve("fixture/Seed.class")));
      return SEED_CLASS_BYTES.get();
    } finally {
      deleteRecursively(tempRoot);
    }
  }

  static CachedFixtureFiles closureFixtureFiles(final FixtureKey key) {
    return CLOSURE_CACHE.computeIfAbsent(key, ClosureFixtureCompileCache::compileFixtureFiles);
  }

  private static CachedFixtureFiles compileFixtureFiles(final FixtureKey key) {
    try {
      final Path stagingRoot = Files.createTempDirectory("elider-closure-fixture-cache");
      try {
        final Path sourceDirectory = Files.createDirectories(stagingRoot.resolve("sources"));
        final Path classes = Files.createDirectories(stagingRoot.resolve(CLASSES_DIRECTORY));
        final Path extraSource = compileClosureSources(sourceDirectory, classes, key);
        final Map<String, byte[]> jarFiles =
            buildClosureJars(stagingRoot, classes, extraSource, key);
        final Map<String, byte[]> sourceFiles = snapshotDirectory(sourceDirectory);
        final Map<String, byte[]> classFiles = snapshotDirectory(classes);
        return new CachedFixtureFiles(sourceFiles, classFiles, jarFiles);
      } finally {
        deleteRecursively(stagingRoot);
      }
    } catch (final IOException exception) {
      throw new UncheckedIOException("Failed to compile closure fixture", exception);
    }
  }

  private static Path compileClosureSources(
      final Path sourceDirectory, final Path classes, final FixtureKey key) throws IOException {
    final String asmField =
        key.optionalAsmReference() ? "public org.objectweb.asm.Label optional; " : "";
    final String entryCode =
        key.resourceOnlyB()
            ? "package closure.a; public class Entry {}"
            : "package closure.a; public class Entry { "
                + asmField
                + "public Object make() { return new closure.b.Middle(); } }";
    final String extraCode =
        key.distinctDuplicateDependencies()
            ? "package closure.a; public class Extra { "
                + "public Object make() { return new closure.c.Leaf(); } }"
            : "package closure.a; public class Extra {}";

    final List<Path> sources = new ArrayList<>();
    sources.add(writeSource(sourceDirectory, "closure/a/Entry.java", entryCode));
    final Path extraSource = writeSource(sourceDirectory, "closure/a/Extra.java", extraCode);
    sources.add(extraSource);
    sources.add(
        writeSource(
            sourceDirectory,
            "closure/b/Middle.java",
            "package closure.b; public class Middle { "
                + "public Object make() { return new closure.c.Leaf(); } }"));
    sources.add(
        writeSource(
            sourceDirectory, "closure/c/Leaf.java", "package closure.c; public class Leaf {}"));
    sources.add(
        writeSource(
            sourceDirectory,
            "closure/d/Ancestor.java",
            "package closure.d; public class Ancestor { "
                + "public Object make() { return new closure.e.Leaf(); } }"));
    sources.add(
        writeSource(
            sourceDirectory, "closure/e/Leaf.java", "package closure.e; public class Leaf {}"));
    sources.add(
        writeSource(
            sourceDirectory, "closure/b/Unused.java", "package closure.b; public class Unused {}"));
    if (key.unusedSecond()) {
      sources.add(
          writeSource(
              sourceDirectory,
              "closure/a/Unused.java",
              "package closure.a; public class Unused {}"));
    }
    if (key.optionalAsmReference()) {
      sources.add(
          writeSource(
              sourceDirectory,
              "org/objectweb/asm/Label.java",
              "package org.objectweb.asm; public class Label {}"));
    }
    CompilationFixtureSupport.compile(classes, sources, key.release());
    return extraSource;
  }

  private static Map<String, byte[]> buildClosureJars(
      final Path stagingRoot, final Path classes, final Path extraSource, final FixtureKey key)
      throws IOException {
    final List<String> firstClasses =
        key.unusedSecond()
            ? List.of("closure/a/Entry.class", EXTRA_CLASS_ENTRY, "closure/a/Unused.class")
            : List.of("closure/a/Entry.class", EXTRA_CLASS_ENTRY);
    final Map<String, String> firstResources =
        key.serviceRootInA()
            ? Map.of(
                FIXTURE_RESOURCE,
                FIXTURE_RESOURCE_CONTENT,
                "META-INF/services/closure.a.Entry",
                "closure.b.Middle\n")
            : Map.of(FIXTURE_RESOURCE, FIXTURE_RESOURCE_CONTENT);
    final Path firstJar =
        jarInDirectory(stagingRoot, "a.jar", classes, firstClasses, firstResources);
    if (key.distinctDuplicateDependencies()) {
      Files.writeString(
          extraSource,
          "package closure.a; public class Extra { "
              + "public Object make() { return new closure.e.Leaf(); } }\n");
      CompilationFixtureSupport.compile(
          classes, List.of(extraSource), "-classpath", classes.toString());
    }
    final List<String> secondClasses;
    if (key.resourceOnlyB()) {
      secondClasses = List.of();
    } else if (key.duplicateClass()) {
      secondClasses =
          key.unusedSecond()
              ? List.of(EXTRA_CLASS_ENTRY, "closure/b/Middle.class", "closure/b/Unused.class")
              : List.of(EXTRA_CLASS_ENTRY, "closure/b/Middle.class");
    } else {
      secondClasses = List.of("closure/b/Middle.class", "closure/b/Unused.class");
    }
    final Path secondJar =
        jarInDirectory(
            stagingRoot,
            "b.jar",
            classes,
            secondClasses,
            Map.of(FIXTURE_RESOURCE, FIXTURE_RESOURCE_CONTENT));
    final Path thirdJar =
        jarInDirectory(stagingRoot, "c.jar", classes, List.of("closure/c/Leaf.class"), Map.of());
    final Path fourthJar =
        jarInDirectory(stagingRoot, "d.jar", classes, List.of(ANCESTOR_CLASS_ENTRY), Map.of());
    final Path fifthJar =
        jarInDirectory(stagingRoot, "e.jar", classes, List.of("closure/e/Leaf.class"), Map.of());
    return Map.of(
        "a.jar", Files.readAllBytes(firstJar),
        "b.jar", Files.readAllBytes(secondJar),
        "c.jar", Files.readAllBytes(thirdJar),
        "d.jar", Files.readAllBytes(fourthJar),
        "e.jar", Files.readAllBytes(fifthJar));
  }

  private static Map<String, byte[]> snapshotDirectory(final Path root) throws IOException {
    final Map<String, byte[]> files = new ConcurrentHashMap<>();
    try (Stream<Path> walk = Files.walk(root)) {
      for (final Path file : walk.filter(Files::isRegularFile).sorted().toList()) {
        files.put(root.relativize(file).toString().replace('\\', '/'), Files.readAllBytes(file));
      }
    }
    return Map.copyOf(files);
  }

  private static void deleteRecursively(final Path root) {
    try (Stream<Path> walk = Files.walk(root)) {
      for (final Path path : walk.sorted(Comparator.reverseOrder()).toList()) {
        Files.deleteIfExists(path);
      }
    } catch (final IOException ignored) {
      // Best-effort cleanup of temp compilation directory.
    }
  }

  private static Path writeSource(
      final Path sourceRoot, final String relativePath, final String content) throws IOException {
    final Path source = sourceRoot.resolve(relativePath);
    Files.createDirectories(source.getParent());
    Files.writeString(source, content + "\n");
    return source;
  }

  private static Path jarInDirectory(
      final Path targetDirectory,
      final String name,
      final Path classes,
      final List<String> classEntries,
      final Map<String, String> resources)
      throws IOException {
    final Path jarPath = targetDirectory.resolve(name);
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jarPath))) {
      for (final String entry : classEntries) {
        writeJarBytes(out, entry, Files.readAllBytes(classes.resolve(entry)));
      }
      for (final Map.Entry<String, String> resource : resources.entrySet()) {
        writeJarBytes(out, resource.getKey(), resource.getValue().getBytes(StandardCharsets.UTF_8));
      }
    }
    return jarPath;
  }

  private static void writeJarBytes(
      final JarOutputStream out, final String entryName, final byte[] bytes) throws IOException {
    out.putNextEntry(new JarEntry(entryName));
    out.write(bytes);
    out.closeEntry();
  }

  record FixtureKey(
      boolean duplicateClass,
      boolean serviceRootInA,
      boolean resourceOnlyB,
      boolean optionalAsmReference,
      int release,
      boolean distinctDuplicateDependencies,
      boolean unusedSecond) {}

  record CachedFixtureFiles(
      Map<String, byte[]> sourceFiles,
      Map<String, byte[]> classFiles,
      Map<String, byte[]> jarFiles) {}
}
