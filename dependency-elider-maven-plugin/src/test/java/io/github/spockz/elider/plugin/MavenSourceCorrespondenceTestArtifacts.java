// WHY: Produces source and binary archives whose bytes exercise the real assessment correspondence
// path.

package io.github.spockz.elider.plugin;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import javax.tools.ToolProvider;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.ArtifactRepository;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResult;

/** Creates source archives and a resolver limited to the Maven boundary. */
@SuppressWarnings("PMD.TooManyMethods") // Archive creation and mutation form one test fixture API.
final class MavenSourceCorrespondenceTestArtifacts {
  /** Resolver method handled by the test proxy. */
  private static final String RESOLVE_ARTIFACT_METHOD = "resolveArtifact";

  /** Physical source archive entry used by the reproduction fixture. */
  /* default */ static final String SOURCE_ENTRY = "src/main/java/org/example/Outer.java";

  private MavenSourceCorrespondenceTestArtifacts() {}

  /* default */ static Archives write(
      final Path directory, final boolean overload, final boolean repeatOwner) throws IOException {
    return write(directory, overload, repeatOwner, false);
  }

  /* default */ static Archives write(
      final Path directory,
      final boolean overload,
      final boolean repeatOwner,
      final boolean manifestClassPath)
      throws IOException {
    final Path sourceRoot = Files.createDirectories(directory.resolve("source-tree/org/example"));
    final Path helperJar = manifestClassPath ? writeManifestHelper(directory) : null;
    final String outerSource = outerSource(overload, manifestClassPath);
    final Path outer = sourceRoot.resolve("Outer.java");
    Files.writeString(outer, outerSource);
    final List<Path> sourceFiles = new ArrayList<>(List.of(outer));
    if (repeatOwner) {
      final Path other = sourceRoot.resolve("Other.java");
      Files.writeString(
          other, "package org.example; public class Other { public void parse() {} }");
      sourceFiles.add(other);
    }
    final Path classes = Files.createDirectories(directory.resolve("compiled"));
    final List<String> compilerArguments =
        Stream.concat(
                Stream.of(
                    "--release",
                    "21",
                    "-encoding",
                    "UTF-8",
                    "-proc:none",
                    "-implicit:none",
                    "-d",
                    classes.toString()),
                sourceFiles.stream().map(Path::toString))
            .toList();
    final List<String> effectiveCompilerArguments =
        manifestClassPath ? withClasspath(compilerArguments, helperJar) : compilerArguments;
    final int exitCode =
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, effectiveCompilerArguments.toArray(String[]::new));
    if (exitCode != 0) {
      throw new IOException("Could not compile source correspondence fixture");
    }
    final Path sourcesJar = directory.resolve("demo-1.0-sources.jar");
    final Path originalJar = directory.resolve("demo-1.0.jar");
    writeJar(sourcesJar, sourceFiles);
    final Manifest manifest = manifestClassPath ? classPathManifest() : null;
    try (JarOutputStream output =
            manifest == null
                ? new JarOutputStream(Files.newOutputStream(originalJar))
                : new JarOutputStream(Files.newOutputStream(originalJar), manifest);
        Stream<Path> paths = Files.walk(classes)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).sorted().toList()) {
        addEntry(
            output,
            classes.relativize(classFile).toString().replace('\\', '/'),
            Files.readAllBytes(classFile));
      }
    }
    return new Archives(originalJar, sourcesJar);
  }

  /* default */ static Path writeEmptyTrimmedJar(final Path path) throws IOException {
    try (JarOutputStream ignored = new JarOutputStream(Files.newOutputStream(path))) {
      return path;
    }
  }

  // Each retained ZIP member needs a fresh entry object when copying the fixture.
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  /* default */ static Path copyJarWithoutEntry(
      final Path original, final Path trimmed, final String omittedEntry) throws IOException {
    try (JarFile input = new JarFile(original.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(trimmed))) {
      final Enumeration<JarEntry> entries = input.entries();
      while (entries.hasMoreElements()) {
        final JarEntry entry = entries.nextElement();
        if (!entry.getName().equals(omittedEntry)) {
          output.putNextEntry(new JarEntry(entry.getName()));
          try (InputStream content = input.getInputStream(entry)) {
            content.transferTo(output);
          }
          output.closeEntry();
        }
      }
    }
    return trimmed;
  }

  /* default */ static RepositorySystem resolver(final Path sourcesJar) {
    return resolver(
        sourcesJar,
        new RemoteRepository.Builder(
                "fixture-remote", "default", "https://repo.example.invalid/maven2")
            .build(),
        ignored -> {});
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals") // Proxy equality must use object identity.
  /* default */ static RepositorySystem resolver(
      final Path sourcesJar,
      final ArtifactRepository repository,
      final Consumer<RepositorySystemSession> sessionObserver) {
    return (RepositorySystem)
        Proxy.newProxyInstance(
            Thread.currentThread().getContextClassLoader(),
            new Class<?>[] {RepositorySystem.class},
            (proxy, method, arguments) -> {
              if (RESOLVE_ARTIFACT_METHOD.equals(method.getName())) {
                sessionObserver.accept((RepositorySystemSession) arguments[0]);
                return resolveSourceArtifact(sourcesJar, repository, arguments);
              }
              return switch (method.getName()) {
                case "toString" -> "Source correspondence resolver fixture";
                case "hashCode" -> System.identityHashCode(proxy);
                case "equals" -> proxy == arguments[0];
                default -> throw new UnsupportedOperationException(method.getName());
              };
            });
  }

  @SuppressWarnings("PMD.LawOfDemeter") // The proxy models the Maven Resolver request boundary.
  private static ArtifactResult resolveSourceArtifact(
      final Path sourcesJar, final ArtifactRepository repository, final Object... arguments) {
    final ArtifactRequest request = (ArtifactRequest) arguments[1];
    final Artifact expected = request.getArtifact();
    final Artifact resolved =
        new DefaultArtifact(
                expected.getGroupId(),
                expected.getArtifactId(),
                expected.getClassifier(),
                expected.getExtension(),
                expected.getVersion())
            .setFile(sourcesJar.toFile());
    return new ArtifactResult(request).setArtifact(resolved).setRepository(repository);
  }

  private static String outerSource(final boolean overload, final boolean manifestClassPath) {
    final String extra = overload ? " public void parse(String value) {}" : "";
    final String externalCall =
        manifestClassPath ? " public int external() { return org.external.Helper.value(); }" : "";
    return "package org.example; public class Outer { public void parse() {}"
        + extra
        + externalCall
        + " public Runnable create() { class Local { void runLocal() {} }"
        + " final Local local = new Local();"
        + " return new Runnable() { public void run() { local.runLocal(); } }; }"
        + " public static class Nested {} } class Sibling {}"
        + " interface SiblingContract {} enum SiblingKind { ONLY }"
        + " @interface SiblingAnnotation {} record SiblingRecord(int value) {}";
  }

  private static Path writeManifestHelper(final Path directory) throws IOException {
    final Path sourceDirectory =
        Files.createDirectories(directory.resolve("helper-source/org/external"));
    final Path helperSource = sourceDirectory.resolve("Helper.java");
    Files.writeString(
        helperSource,
        "package org.external; public class Helper { public static int value() { return 7; } }");
    final Path classes = Files.createDirectories(directory.resolve("helper-classes"));
    final int exitCode =
        ToolProvider.getSystemJavaCompiler()
            .run(
                null,
                null,
                null,
                "--release",
                "21",
                "-d",
                classes.toString(),
                helperSource.toString());
    if (exitCode != 0) {
      throw new IOException("Could not compile manifest helper fixture");
    }
    final Path helperJar = directory.resolve("helper.jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(helperJar));
        Stream<Path> paths = Files.walk(classes)) {
      for (final Path classFile : paths.filter(Files::isRegularFile).sorted().toList()) {
        addEntry(
            output,
            classes.relativize(classFile).toString().replace('\\', '/'),
            Files.readAllBytes(classFile));
      }
    }
    return helperJar;
  }

  private static List<String> withClasspath(final List<String> arguments, final Path helperJar) {
    final int destination = arguments.indexOf("-d");
    final List<String> result = new ArrayList<>(arguments);
    result.add(destination, "-classpath");
    result.add(destination + 1, helperJar.toString());
    return List.copyOf(result);
  }

  private static Manifest classPathManifest() {
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(Attributes.Name.CLASS_PATH, "helper.jar");
    return manifest;
  }

  private static void writeJar(final Path jar, final List<Path> sources) throws IOException {
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      for (final Path source : sources) {
        final String entry = "org/example/" + source.getFileName();
        addEntry(output, entry, Files.readAllBytes(source));
      }
    }
  }

  private static void addEntry(final JarOutputStream output, final String name, final byte[] bytes)
      throws IOException {
    output.putNextEntry(new JarEntry(name));
    output.write(bytes);
    output.closeEntry();
  }

  /* default */ static void removeOriginalEntry(final Path jar, final String name)
      throws IOException {
    rewriteEntry(jar, name, null, true);
  }

  /* default */ static void addOriginalEntry(final Path jar, final String name, final byte[] bytes)
      throws IOException {
    rewriteEntry(jar, name, bytes, false);
  }

  /* default */ static void replaceOriginalEntry(
      final Path jar, final String name, final byte[] bytes) throws IOException {
    rewriteEntry(jar, name, bytes, false);
  }

  /* default */ static void addSourcesEntry(final Path jar, final String name, final byte[] bytes)
      throws IOException {
    rewriteEntry(jar, name, bytes, false);
  }

  @SuppressWarnings("PMD.UseConcurrentHashMap") // The map is local to one fixture mutation.
  private static void rewriteEntry(
      final Path jar, final String name, final byte[] bytes, final boolean remove)
      throws IOException {
    final Map<String, byte[]> entries = new HashMap<>();
    final Manifest manifest;
    try (JarFile input = new JarFile(jar.toFile())) {
      manifest = manifest(input);
      for (final JarEntry entry : input.stream().toList()) {
        if (!entry.isDirectory() && !JarFile.MANIFEST_NAME.equals(entry.getName())) {
          try (InputStream stream = input.getInputStream(entry)) {
            entries.put(entry.getName(), stream.readAllBytes());
          }
        }
      }
    }
    if (remove) {
      entries.remove(name);
    } else {
      entries.put(name, bytes.clone());
    }
    final Path temporary = Files.createTempFile(jar.getParent(), "rewrite-", ".jar");
    try {
      try (JarOutputStream output =
          manifest == null
              ? new JarOutputStream(Files.newOutputStream(temporary))
              : new JarOutputStream(Files.newOutputStream(temporary), manifest)) {
        for (final Map.Entry<String, byte[]> entry :
            entries.entrySet().stream().sorted(Map.Entry.comparingByKey()).toList()) {
          addEntry(output, entry.getKey(), entry.getValue());
        }
      }
      Files.move(temporary, jar, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  private static Manifest manifest(final JarFile input) throws IOException {
    return input.getManifest();
  }

  /* default */ record Archives(Path originalJar, Path sourcesJar) {}
}
