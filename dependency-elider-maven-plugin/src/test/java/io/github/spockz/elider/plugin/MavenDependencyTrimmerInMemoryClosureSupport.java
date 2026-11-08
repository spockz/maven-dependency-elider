/* WHY: Shares bytecode/JAR construction and Maven graph fixtures across closure tests. */

package io.github.spockz.elider.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;

/** Provides reusable immutable-input fixtures for closure tests. */
@SuppressWarnings({"PMD.CommentDefaultAccessModifier", "PMD.TooManyMethods"})
class MavenDependencyTrimmerInMemoryClosureSupport {

  /** Maven field name used for project injection. */
  protected static final String PROJECT_FIELD = "project";

  /** Maven field name used for session injection. */
  protected static final String SESSION_FIELD = "session";

  /** Maven field name used for runtime evidence inputs. */
  protected static final String TRACE_FILES_FIELD = "traceFiles";

  /** Maven field name used for closed-world evidence mode. */
  protected static final String CLOSED_WORLD_FIELD = "closedWorld";

  /** Class name used by generated modular fixture archives. */
  private static final String FIXTURE_MODULE_CLASS = "module-info";

  /** Service descriptor parsed by the goal output fixture. */
  private static final String FIXTURE_SERVICE_PATH = "META-INF/services/fixture.service.Spi";

  /** Multi-release entry prefix used by generated upper-tier archives. */
  private static final String VERSIONED_ENTRY_PREFIX = "META-INF/versions/";

  /** Test goal report parser shared by Analyze and Elide output checks. */
  protected final ObjectMapper reportObjectMapper = new ObjectMapper();

  /** Fixture coordinates are shared by generated test artifacts. */
  private static final String GROUP_ID = "fixture";

  /** Fixture artifact versions are stable across scenarios. */
  private static final String VERSION = "1.0";

  /** The direct fixture dependency uses Maven compile scope. */
  private static final String COMPILE_SCOPE = "compile";

  /** Transitive fixture artifacts use Maven runtime scope. */
  private static final String RUNTIME_SCOPE = "runtime";

  /** Entry shared by duplicate-owner fixtures and their expected archives. */
  private static final String EXTRA_CLASS_ENTRY = "closure/a/Extra.class";

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

  /** Builds a fixture with optional unresolved ASM references. */
  protected Fixture fixture(
      final boolean duplicateClass,
      final boolean serviceRootInA,
      final boolean resourceOnlyB,
      final boolean optionalAsmReference)
      throws IOException {
    return fixture(
        duplicateClass, serviceRootInA, resourceOnlyB, optionalAsmReference, 21, COMPILE_SCOPE);
  }

  /** Builds a release-specific fixture for multi-tier archive analysis. */
  protected Fixture fixture(
      final boolean duplicateClass,
      final boolean serviceRootInA,
      final boolean resourceOnlyB,
      final boolean optionalAsmReference,
      final int release)
      throws IOException {
    return fixture(
        duplicateClass,
        serviceRootInA,
        resourceOnlyB,
        optionalAsmReference,
        release,
        COMPILE_SCOPE);
  }

  private Fixture fixture(
      final boolean duplicateClass,
      final boolean serviceRootInA,
      final boolean resourceOnlyB,
      final boolean optionalAsmReference,
      final int release,
      final String firstArtifactScope)
      throws IOException {
    return fixtureWithOptions(
        duplicateClass,
        serviceRootInA,
        resourceOnlyB,
        optionalAsmReference,
        release,
        firstArtifactScope,
        false,
        RUNTIME_SCOPE,
        false);
  }

  /** Builds duplicate owners with an unrelated class in the second archive. */
  protected Fixture fixtureWithDuplicateAndUnusedSecond() throws IOException {
    return fixtureWithDuplicateAndUnusedSecond(21);
  }

  /** Builds runtime duplicate owners for a selected target release. */
  protected Fixture fixtureWithDuplicateAndUnusedSecond(final int release) throws IOException {
    return fixtureWithOptions(
        true, false, false, false, release, RUNTIME_SCOPE, false, RUNTIME_SCOPE, true);
  }

  /** Builds two duplicate variants that link to different dropped artifacts. */
  protected Fixture fixtureWithDistinctDuplicateDependencies() throws IOException {
    return fixtureWithOptions(
        true, false, false, false, 21, COMPILE_SCOPE, true, RUNTIME_SCOPE, false);
  }

  /** Builds duplicate owners in compile and provided scope. */
  protected Fixture fixtureWithProvidedDuplicate() throws IOException {
    return fixtureWithOptions(
        true, false, false, false, 21, COMPILE_SCOPE, false, "provided", false);
  }

  private Fixture fixtureWithOptions(
      final boolean duplicateClass,
      final boolean serviceRootInA,
      final boolean resourceOnlyB,
      final boolean optionalAsmReference,
      final int release,
      final String firstArtifactScope,
      final boolean distinctDuplicateDependencies,
      final String secondArtifactScope,
      final boolean unusedSecond)
      throws IOException {
    final Path sourceDirectory = Files.createDirectories(temporaryDirectory.resolve("sources"));
    final Path classes = Files.createDirectories(temporaryDirectory.resolve("classes"));
    final Path firstSource =
        writeSource(
            sourceDirectory,
            "closure/a/Entry.java",
            entrySource(resourceOnlyB, optionalAsmReference));
    final Path optionalAsmSource =
        optionalAsmReference
            ? writeSource(
                sourceDirectory,
                "org/objectweb/asm/Label.java",
                "package org.objectweb.asm; public class Label {}")
            : null;
    final Path extraSource =
        writeSource(
            sourceDirectory, "closure/a/Extra.java", extraSource(distinctDuplicateDependencies));
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
    final Path unusedSecondSource =
        writeSource(
            sourceDirectory, "closure/b/Unused.java", "package closure.b; public class Unused {}");
    final Path unusedFirstSource =
        unusedSecond
            ? writeSource(
                sourceDirectory,
                "closure/a/Unused.java",
                "package closure.a; public class Unused {}")
            : null;
    final List<Path> sources =
        new ArrayList<>(
            List.of(
                firstSource,
                extraSource,
                secondSource,
                thirdSource,
                fourthSource,
                fifthSource,
                unusedSecondSource));
    if (unusedFirstSource != null) {
      sources.add(unusedFirstSource);
    }
    if (optionalAsmSource != null) {
      sources.add(optionalAsmSource);
    }
    io.github.spockz.elider.test.CompilationFixtureSupport.compile(classes, sources, release);
    final Path firstArtifactPath =
        jar(
            "a.jar",
            classes,
            unusedSecond
                ? List.of("closure/a/Entry.class", EXTRA_CLASS_ENTRY, "closure/a/Unused.class")
                : List.of("closure/a/Entry.class", EXTRA_CLASS_ENTRY),
            serviceRootInA
                ? Map.of(
                    "data/fixture.txt", "preserve this resource\n",
                    "META-INF/services/closure.a.Entry", "closure.b.Middle\n")
                : Map.of("data/fixture.txt", "preserve this resource\n"));
    if (distinctDuplicateDependencies) {
      Files.writeString(
          extraSource,
          "package closure.a; public class Extra { "
              + "public Object make() { return new closure.e.Leaf(); } }\n");
      io.github.spockz.elider.test.CompilationFixtureSupport.compile(
          classes, List.of(extraSource), "-classpath", classes.toString());
    }
    final List<String> secondClasses =
        secondArtifactClasses(resourceOnlyB, duplicateClass, unusedSecond);
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
        fifthArtifactPath,
        release,
        firstArtifactScope,
        secondArtifactScope);
  }

  private static String entrySource(
      final boolean resourceOnlyB, final boolean optionalAsmReference) {
    if (resourceOnlyB) {
      return "package closure.a; public class Entry {}";
    }
    final String asmField = optionalAsmReference ? "public org.objectweb.asm.Label optional; " : "";
    return "package closure.a; public class Entry { "
        + asmField
        + "public Object make() { return new closure.b.Middle(); } }";
  }

  private static String extraSource(final boolean distinctDuplicateDependencies) {
    return distinctDuplicateDependencies
        ? "package closure.a; public class Extra { "
            + "public Object make() { return new closure.c.Leaf(); } }"
        : "package closure.a; public class Extra {}";
  }

  private static List<String> secondArtifactClasses(
      final boolean resourceOnlyB, final boolean duplicateClass, final boolean unusedSecond) {
    if (resourceOnlyB) {
      return List.of();
    }
    if (!duplicateClass) {
      return List.of("closure/b/Middle.class", "closure/b/Unused.class");
    }
    return unusedSecond
        ? List.of(EXTRA_CLASS_ENTRY, "closure/b/Middle.class", "closure/b/Unused.class")
        : List.of(EXTRA_CLASS_ENTRY, "closure/b/Middle.class");
  }

  /** Builds a fixture whose first archive is visible only at runtime. */
  protected Fixture fixtureWithRuntimeA() throws IOException {
    return fixture(false, false, false, false, 21, RUNTIME_SCOPE);
  }

  /** Builds a runtime-scoped first artifact with a selected base class release. */
  protected Fixture fixtureWithRuntimeA(final int release) throws IOException {
    return fixture(false, false, false, false, release, RUNTIME_SCOPE);
  }

  /** Builds a provided-scope modular artifact. */
  protected Fixture fixtureWithProvidedA(final int release) throws IOException {
    return fixtureWithOptions(
        false, false, false, false, release, "provided", false, RUNTIME_SCOPE, false);
  }

  /** Builds runtime A without bytecode links to resource-only B. */
  protected Fixture fixtureWithRuntimeFirstAndResourceOnlySecond() throws IOException {
    return fixture(false, false, true, false, 21, RUNTIME_SCOPE);
  }

  /** Builds a fixture whose entry class has an unresolved optional ASM type. */
  protected Fixture fixtureWithOptionalAsmReference() throws IOException {
    return fixture(false, false, false, true);
  }

  /** Creates minimal class bytes for unrelated archive entries. */
  protected static byte[] emptyClassBytes(final String internalName) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);
    writer.visitEnd();
    return writer.toByteArray();
  }

  private Path writeSource(final Path root, final String relative, final String content)
      throws IOException {
    final Path source = root.resolve(relative);
    Files.createDirectories(source.getParent());
    Files.writeString(source, content + "\n");
    return source;
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
  @SuppressWarnings("PMD.CouplingBetweenObjects")
  protected final class Fixture {
    /** Full resolved Maven artifact inventory. */
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots;

    /** Project associated with the inventory. */
    final MavenProject project;

    /** Pre-scanned complete JAR inventory. */
    final TrimScanInputs scanInputs;

    /** Mutable Maven artifact objects owned by the project fixture. */
    final List<Artifact> projectArtifacts;

    /* package */ MavenProject projectValue() {
      return project;
    }

    /* package */ List<Artifact> projectArtifactValues() {
      return projectArtifacts;
    }

    /* package */ List<ElisionAnalysisModel.ArtifactSnapshot> snapshotValues() {
      return snapshots;
    }

    private Fixture(
        final Path firstArtifactPath,
        final Path secondArtifactPath,
        final Path thirdArtifactPath,
        final Path fourthArtifactPath,
        final Path fifthArtifactPath,
        final int release,
        final String firstArtifactScope,
        final String secondArtifactScope)
        throws IOException {
      final Artifact firstArtifact = artifact("a", firstArtifactPath, firstArtifactScope);
      final Artifact secondArtifact = artifact("b", secondArtifactPath, secondArtifactScope);
      final Artifact thirdArtifact = artifact("c", thirdArtifactPath, RUNTIME_SCOPE);
      final Artifact fourthArtifact = artifact("d", fourthArtifactPath, RUNTIME_SCOPE);
      final Artifact fifthArtifact = artifact("e", fifthArtifactPath, RUNTIME_SCOPE);
      projectArtifacts =
          List.of(firstArtifact, secondArtifact, thirdArtifact, fourthArtifact, fifthArtifact);
      snapshots = MavenArtifactInventory.snapshots(projectArtifacts);
      project = new MavenProject();
      project.setArtifacts(Set.copyOf(projectArtifacts));
      project.setGroupId(GROUP_ID);
      project.setArtifactId("consumer");
      project.setVersion(VERSION);
      project.setFile(temporaryDirectory.resolve("consumer-pom.xml").toFile());
      project.getProperties().setProperty("maven.compiler.release", Integer.toString(release));
      final Build build = new Build();
      build.setDirectory(temporaryDirectory.resolve("build").toString());
      project.setBuild(build);
      final List<ArtifactFileRef> refs = new ArrayList<>();
      for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : snapshots) {
        refs.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
      }
      final ArtifactClassIndex index = new JarIndexScanner().scan(refs);
      final Map<Path, DependencyDynamicRoots.RootScan> dynamic =
          snapshots.stream()
              .collect(
                  java.util.stream.Collectors.toMap(
                      ElisionAnalysisModel.ArtifactSnapshot::filePath, ignored -> EMPTY_ROOT_SCAN));
      scanInputs = new TrimScanInputs(index, dynamic);
    }

    /** Strictly analyzes the complete candidate archive inventory. */
    TrimAnalysisResult analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<TrimArtifactRootKey, Set<String>> roots)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(retained, unchanged, roots, Map.of(), List.of());
    }

    /** Analyzes the complete inventory while tolerating selected duplicate classes. */
    TrimAnalysisResult analyze(
        final Set<ArtifactCoordinate> retained, final DuplicateClassPolicy duplicates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(retained, Set.of(), Map.of(), Map.of(), List.of(), duplicates);
    }

    /** Attaches dynamic roots to each candidate archive before strict analysis. */
    TrimAnalysisResult analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<TrimArtifactRootKey, Set<String>> roots,
        final Map<Path, Set<String>> dynamicRoots,
        final List<String> passThroughCoordinates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(
          retained,
          unchanged,
          roots,
          dynamicRoots,
          passThroughCoordinates,
          DuplicateClassPolicy.NONE);
    }

    private TrimAnalysisResult analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<TrimArtifactRootKey, Set<String>> roots,
        final Map<Path, Set<String>> dynamicRoots,
        final List<String> passThroughCoordinates,
        final DuplicateClassPolicy duplicates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(
          retained,
          unchanged,
          roots,
          dynamicRoots,
          passThroughCoordinates,
          duplicates,
          "closure.a.Entry");
    }

    private TrimAnalysisResult analyze(
        final Set<ArtifactCoordinate> retained,
        final Set<ArtifactCoordinate> unchanged,
        final Map<TrimArtifactRootKey, Set<String>> roots,
        final Map<Path, Set<String>> dynamicRoots,
        final List<String> passThroughCoordinates,
        final DuplicateClassPolicy duplicates,
        final String traceRoot)
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
          new TrimRequest(
              project,
              null,
              snapshots,
              new TrimScanInputs(scanInputs.classIndex(), scans),
              retained,
              new TrimEvidence(TraceData.of(Set.of(traceRoot)), Set.of(), Set.of(), Set.of()),
              new TrimPolicy(
                  List.of(),
                  false,
                  passThroughCoordinates,
                  false,
                  MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                  true,
                  true,
                  MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                  duplicates)),
          roots,
          unchanged);
    }

    TrimAnalysisResult analyzeDuplicateRoot(
        final Set<ArtifactCoordinate> retained, final DuplicateClassPolicy duplicates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyzeDuplicateRoot(retained, duplicates, List.of());
    }

    TrimAnalysisResult analyzeDuplicateRoot(
        final Set<ArtifactCoordinate> retained,
        final DuplicateClassPolicy duplicates,
        final List<String> passThroughCoordinates)
        throws IOException, org.apache.maven.plugin.MojoFailureException {
      return analyze(
          retained,
          Set.of(),
          Map.of(),
          Map.of(),
          passThroughCoordinates,
          duplicates,
          "closure.a.Extra");
    }

    MavenProject mavenProject() {
      return project;
    }

    List<ElisionAnalysisModel.ArtifactSnapshot> allSnapshots() {
      return snapshots;
    }

    Path addVersionedClassToC() throws IOException {
      final Path path = snapshot("c").filePath();
      final Path versionedClasses = temporaryDirectory.resolve("version-9-classes");
      io.github.spockz.elider.test.CompilationFixtureSupport.compile(
          versionedClasses, List.of(temporaryDirectory.resolve("sources/closure/c/Leaf.java")), 9);
      final byte[] content = Files.readAllBytes(versionedClasses.resolve("closure/c/Leaf.class"));
      final byte[] baseContent =
          Files.readAllBytes(temporaryDirectory.resolve("classes/closure/c/Leaf.class"));
      final Manifest manifest = new Manifest();
      manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
      manifest.getMainAttributes().putValue("Multi-Release", "true");
      try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path), manifest)) {
        output.putNextEntry(new JarEntry("closure/c/Leaf.class"));
        output.write(baseContent);
        output.closeEntry();
        output.putNextEntry(new JarEntry("META-INF/versions/9/closure/c/Leaf.class"));
        output.write(content);
        output.closeEntry();
      }
      return path;
    }

    // Recreate each ZIP entry while appending metadata to the archive under test.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    void addUnknownNativeImageArgsToA() throws IOException {
      final Path path = snapshot("a").filePath();
      final Path staged = temporaryDirectory.resolve("a-with-unknown-native-image.jar");
      try (java.util.jar.JarFile archive = new java.util.jar.JarFile(path.toFile());
          JarOutputStream output = new JarOutputStream(Files.newOutputStream(staged))) {
        final java.util.Enumeration<JarEntry> entries = archive.entries();
        while (entries.hasMoreElements()) {
          final JarEntry entry = entries.nextElement();
          output.putNextEntry(new JarEntry(entry.getName()));
          try (java.io.InputStream input = archive.getInputStream(entry)) {
            input.transferTo(output);
          }
          output.closeEntry();
        }
        output.putNextEntry(new JarEntry("META-INF/native-image/test/native-image.properties"));
        output.write(
            "Args = -H:Class=closure.a.Extra -H:Class=closure.b.Unused -H:CustomUnknown=value\n"
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
        output.closeEntry();
      }
      Files.move(staged, path, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    List<Artifact> artifacts() {
      return projectArtifacts;
    }

    ElisionAnalysisModel.ArtifactSnapshot snapshot(final String artifactId) {
      return snapshots.stream()
          .filter(snapshot -> snapshot.coordinate().artifactId().equals(artifactId))
          .findFirst()
          .orElseThrow();
    }

    ArtifactCoordinate coordinate(final String artifactId) {
      return snapshot(artifactId).coordinate();
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
