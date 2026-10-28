/* WHY: Shares bytecode/JAR construction and Maven graph fixtures across closure tests. */

package io.github.spockz.elider.plugin;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.ArtifactClassIndex;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipOutputStream;
import javax.tools.ToolProvider;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.io.TempDir;

/** Provides reusable immutable-input fixtures for closure tests. */
@SuppressWarnings("PMD.CommentDefaultAccessModifier")
class MavenDependencyTrimmerInMemoryClosureSupport {

  /** Fixture coordinates are shared by generated test artifacts. */
  private static final String GROUP_ID = "fixture";

  /** Fixture artifact versions are stable across scenarios. */
  private static final String VERSION = "1.0";

  /** The direct fixture dependency uses Maven compile scope. */
  private static final String COMPILE_SCOPE = "compile";

  /** Transitive fixture artifacts use Maven runtime scope. */
  private static final String RUNTIME_SCOPE = "runtime";

  /** Empty metadata scan reused when no artifact-specific roots are configured. */
  private static final DependencyDynamicRoots.RootScan EMPTY_ROOT_SCAN =
      new DependencyDynamicRoots.RootScan(Set.of(), true);

  /** Temporary root used for generated sources, classes, and archives. */
  @TempDir protected Path temporaryDirectory;

  /** JUnit fills the temporary directory field after constructing this fixture base. */
  @SuppressWarnings("PMD.UncommentedEmptyConstructor")
  MavenDependencyTrimmerInMemoryClosureSupport() {}

  /** Builds the standard complete inventory fixture. */
  protected Fixture fixture(final boolean duplicateClass) throws IOException {
    return fixture(duplicateClass, false);
  }

  /** Builds a fixture with optional duplicate ownership or service metadata. */
  protected Fixture fixture(final boolean duplicateClass, final boolean serviceRootInA)
      throws IOException {
    return fixture(duplicateClass, serviceRootInA, false);
  }

  /** Builds a fixture with a resource-only second artifact when requested. */
  protected Fixture fixture(
      final boolean duplicateClass, final boolean serviceRootInA, final boolean resourceOnlyB)
      throws IOException {
    return fixture(duplicateClass, serviceRootInA, resourceOnlyB, false);
  }

  private Fixture fixture(
      final boolean duplicateClass,
      final boolean serviceRootInA,
      final boolean resourceOnlyB,
      final boolean optionalAsmReference)
      throws IOException {
    final Path sourceDirectory = Files.createDirectories(temporaryDirectory.resolve("sources"));
    final Path classes = Files.createDirectories(temporaryDirectory.resolve("classes"));
    final Path firstSource =
        writeSource(
            sourceDirectory,
            "closure/a/Entry.java",
            resourceOnlyB
                ? "package closure.a; public class Entry {}"
                : optionalAsmReference
                    ? "package closure.a; public class Entry { "
                        + "public org.objectweb.asm.Label optional; "
                        + "public Object make() { return new closure.b.Middle(); } }"
                    : "package closure.a; public class Entry { "
                        + "public Object make() { return new closure.b.Middle(); } }");
    final Path optionalAsmSource =
        optionalAsmReference
            ? writeSource(
                sourceDirectory,
                "org/objectweb/asm/Label.java",
                "package org.objectweb.asm; public class Label {}")
            : null;
    final Path extraSource =
        writeSource(
            sourceDirectory, "closure/a/Extra.java", "package closure.a; public class Extra {}");
    final Path secondSource =
        writeSource(
            sourceDirectory,
            "closure/b/Middle.java",
            "package closure.b; public class Middle { "
                + "public Object make() { return new closure.c.Leaf(); } }");
    final Path thirdSource =
        writeSource(
            sourceDirectory, "closure/c/Leaf.java", "package closure.c; public class Leaf {}");
    final Path fourthSource =
        writeSource(
            sourceDirectory,
            "closure/d/Ancestor.java",
            "package closure.d; public class Ancestor { "
                + "public Object make() { return new closure.e.Leaf(); } }");
    final Path fifthSource =
        writeSource(
            sourceDirectory, "closure/e/Leaf.java", "package closure.e; public class Leaf {}");
    final List<Path> sources =
        new ArrayList<>(
            List.of(
                firstSource, extraSource, secondSource, thirdSource, fourthSource, fifthSource));
    if (optionalAsmSource != null) {
      sources.add(optionalAsmSource);
    }
    compile(classes, sources);
    final Path firstArtifactPath =
        jar(
            "a.jar",
            classes,
            List.of("closure/a/Entry.class", "closure/a/Extra.class"),
            firstArtifactResources(serviceRootInA));
    final List<String> secondClasses =
        resourceOnlyB
            ? List.of()
            : duplicateClass
                ? List.of("closure/a/Extra.class", "closure/b/Middle.class")
                : List.of("closure/b/Middle.class");
    final Path secondArtifactPath =
        jar(
            "b.jar",
            classes,
            secondClasses,
            Map.of("data/fixture.txt", "preserve this resource\n"));
    final Path thirdArtifactPath = jar("c.jar", classes, List.of("closure/c/Leaf.class"));
    final Path fourthArtifactPath = jar("d.jar", classes, List.of("closure/d/Ancestor.class"));
    final Path fifthArtifactPath = jar("e.jar", classes, List.of("closure/e/Leaf.class"));
    return new Fixture(
        firstArtifactPath,
        secondArtifactPath,
        thirdArtifactPath,
        fourthArtifactPath,
        fifthArtifactPath);
  }

  /** Builds a fixture whose entry class has an unresolved optional ASM type. */
  protected Fixture fixtureWithOptionalAsmReference() throws IOException {
    return fixture(false, false, false, true);
  }

  private static Map<String, String> firstArtifactResources(final boolean serviceRootInA) {
    if (serviceRootInA) {
      return Map.of(
          "data/fixture.txt", "preserve this resource\n",
          "META-INF/services/closure.a.Entry", "closure.b.Middle\n");
    }
    return Map.of("data/fixture.txt", "preserve this resource\n");
  }

  private Path writeSource(final Path root, final String relative, final String content)
      throws IOException {
    final Path source = root.resolve(relative);
    Files.createDirectories(source.getParent());
    Files.writeString(source, content + "\n");
    return source;
  }

  private static void compile(final Path output, final List<Path> sources) throws IOException {
    final List<String> arguments =
        new ArrayList<>(List.of("--release", "21", "-d", output.toString()));
    sources.forEach(source -> arguments.add(source.toString()));
    final int result =
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, arguments.toArray(String[]::new));
    if (result != 0) {
      throw new IOException("Could not compile the bytecode closure fixture");
    }
  }

  private Path jar(final String name, final Path classes, final List<String> entries)
      throws IOException {
    return jar(name, classes, entries, Map.of());
  }

  /** Creates one archive while each entry receives its own ZIP metadata object. */
  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path jar(
      final String name,
      final Path classes,
      final List<String> entries,
      final Map<String, String> textEntries)
      throws IOException {
    final Path jar = temporaryDirectory.resolve(name);
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
      for (final String entry : entries) {
        output.putNextEntry(new JarEntry(entry));
        Files.copy(classes.resolve(entry), output);
        output.closeEntry();
      }
      for (final Map.Entry<String, String> entry : textEntries.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey()));
        output.write(entry.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
      }
    }
    return jar;
  }

  /** Fixture whose generated inputs stay within its temporary test directory. */
  protected final class Fixture {
    /** Full resolved Maven artifact inventory. */
    final List<MavenElisionService.ArtifactSnapshot> snapshots;

    /** Project associated with the inventory. */
    final MavenProject project;

    /** Pre-scanned complete JAR inventory. */
    final MavenDependencyTrimmer.ScanInputs scanInputs;

    /** Mutable Maven artifact objects owned by the project fixture. */
    final List<Artifact> projectArtifacts;

    private Fixture(
        final Path firstArtifactPath,
        final Path secondArtifactPath,
        final Path thirdArtifactPath,
        final Path fourthArtifactPath,
        final Path fifthArtifactPath)
        throws IOException {
      final Artifact firstArtifact = artifact("a", firstArtifactPath);
      final Artifact secondArtifact = artifact("b", secondArtifactPath, RUNTIME_SCOPE);
      final Artifact thirdArtifact = artifact("c", thirdArtifactPath, RUNTIME_SCOPE);
      final Artifact fourthArtifact = artifact("d", fourthArtifactPath, RUNTIME_SCOPE);
      final Artifact fifthArtifact = artifact("e", fifthArtifactPath, RUNTIME_SCOPE);
      projectArtifacts =
          List.of(firstArtifact, secondArtifact, thirdArtifact, fourthArtifact, fifthArtifact);
      snapshots = MavenElisionService.snapshots(projectArtifacts);
      project = new MavenProject();
      project.setArtifacts(Set.copyOf(projectArtifacts));
      project.setGroupId(GROUP_ID);
      project.setArtifactId("consumer");
      project.setVersion(VERSION);
      project.setFile(temporaryDirectory.resolve("consumer-pom.xml").toFile());
      project.getProperties().setProperty("maven.compiler.release", "21");
      final Build build = new Build();
      build.setDirectory(temporaryDirectory.resolve("build").toString());
      project.setBuild(build);
      final List<ArtifactFileRef> refs = new ArrayList<>();
      for (final MavenElisionService.ArtifactSnapshot snapshot : snapshots) {
        refs.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
      final ArtifactClassIndex index = new JarIndexScanner().scan(refs);
      final Map<Path, DependencyDynamicRoots.RootScan> dynamic =
          snapshots.stream()
              .collect(
                  java.util.stream.Collectors.toMap(
                      MavenElisionService.ArtifactSnapshot::filePath, ignored -> EMPTY_ROOT_SCAN));
      scanInputs = new MavenDependencyTrimmer.ScanInputs(index, dynamic);
    }

    /** Strictly analyzes the complete candidate archive inventory. */
    MavenDependencyTrimmer.InMemoryAnalysis analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> roots)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(retained, unchanged, roots, Map.of(), List.of());
    }

    /** Attaches dynamic roots to each candidate archive before strict analysis. */
    MavenDependencyTrimmer.InMemoryAnalysis analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<MavenDependencyTrimmer.ArtifactRootKey, Set<String>> roots,
        final Map<Path, Set<String>> dynamicRoots,
        final List<String> passThroughCoordinates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      final Map<Path, DependencyDynamicRoots.RootScan> scans =
          snapshots.stream()
              .collect(
                  java.util.stream.Collectors.toMap(
                      snapshot -> snapshot.filePath().toAbsolutePath().normalize(),
                      snapshot ->
                          new DependencyDynamicRoots.RootScan(
                              dynamicRoots.getOrDefault(
                                  snapshot.filePath().toAbsolutePath().normalize(), Set.of()),
                              true)));
      return MavenDependencyTrimmer.analyzeInMemory(
          new MavenDependencyTrimmer.TrimRequest(
              project,
              null,
              snapshots,
              new MavenDependencyTrimmer.ScanInputs(scanInputs.classIndex(), scans),
              retained,
              TraceData.of(Set.of("closure.a.Entry")),
              Set.of(),
              Set.of(),
              Set.of(),
              List.of(),
              false,
              passThroughCoordinates,
              false),
          roots,
          unchanged);
    }

    MavenProject mavenProject() {
      return project;
    }

    List<MavenElisionService.ArtifactSnapshot> allSnapshots() {
      return snapshots;
    }

    Path addVersionedClassToC() throws IOException {
      final Path path = snapshot("c").filePath();
      final byte[] content =
          Files.readAllBytes(temporaryDirectory.resolve("classes/closure/c/Leaf.class"));
      try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(path))) {
        output.putNextEntry(new java.util.zip.ZipEntry("META-INF/versions/9/closure/c/Leaf.class"));
        output.write(content);
        output.closeEntry();
      }
      return path;
    }

    List<Artifact> artifacts() {
      return projectArtifacts;
    }

    MavenElisionService.ArtifactSnapshot snapshot(final String artifactId) {
      return snapshots.stream()
          .filter(snapshot -> snapshot.coordinate().artifactId().equals(artifactId))
          .findFirst()
          .orElseThrow();
    }

    ArtifactCoordinate coordinate(final String artifactId) {
      return snapshot(artifactId).coordinate();
    }

    private Artifact artifact(final String artifactId, final Path path) {
      return artifact(artifactId, path, COMPILE_SCOPE);
    }

    private Artifact artifact(final String artifactId, final Path path, final String scope) {
      final Artifact artifact =
          new DefaultArtifact(
              GROUP_ID, artifactId, VERSION, scope, "jar", null, new DefaultArtifactHandler("jar"));
      artifact.setFile(path.toFile());
      return artifact;
    }
  }
}
