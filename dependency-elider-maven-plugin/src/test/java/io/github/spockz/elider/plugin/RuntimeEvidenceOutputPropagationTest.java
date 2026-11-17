/* WHY: Proves the admitted runtime policy changes real effective trim outputs. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.test.CompilationFixtureSupport;
import io.github.spockz.elider.trimmer.ArtifactTrimRecord;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

/** Checks that service admission reaches bytecode closure and archive generation. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.TooManyMethods",
  "PMD.LawOfDemeter",
  "PMD.AvoidInstantiatingObjectsInLoops"
})
final class RuntimeEvidenceOutputPropagationTest extends MavenElisionServiceEffectiveOutputSupport {
  /** Class admitted by both runtime evidence formats. */
  private static final String ENTRY = "closure/a/Entry";

  @Test
  void closedWorldChangesSingleReleaseProviderOutput() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA();
    final Path evidence = trace(temporaryDirectory, ENTRY);
    final OutputObservation conservative = output(fixture, evidence, false);
    final OutputObservation closedWorld = output(fixture, evidence, true);

    assertAll(
        "closed-world evidence changes the provider kept in a real trim output",
        () -> assertThat(conservative.allowedClasses()).contains(ENTRY.replace('/', '.')),
        () -> assertThat(closedWorld.allowedClasses()).contains(ENTRY.replace('/', '.')),
        () -> assertThat(conservative.retainedProviders()).contains("b"),
        () -> assertThat(closedWorld.elidedProviders()).contains("b"),
        () -> assertThat(conservative.generatedArtifacts()).contains("a"),
        () -> assertThat(closedWorld.generatedArtifacts()).contains("a"),
        () -> assertThat(conservative.middleEntries()).contains("closure/b/Middle.class"),
        () -> assertThat(conservative.middleEntries()).doesNotContain("closure/b/Unused.class"),
        () -> assertThat(closedWorld.middleEntries()).isEmpty());
  }

  @Test
  void closedWorldTransformedSubclassRunsInFreshJvmAndFailsOnOmittedPath() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA();
    final Path subSource = Files.createDirectories(temporaryDirectory.resolve("subclass-source"));
    final Path baseJava = subSource.resolve("fixture/sub/BaseA.java");
    final Path liveJava = subSource.resolve("fixture/sub/LiveA.java");
    Files.createDirectories(baseJava.getParent());
    Files.writeString(
        baseJava,
        "package fixture.sub; public class BaseA { public String base() { return \"base\"; } }\n");
    Files.writeString(
        liveJava,
        "package fixture.sub;\n"
            + "public final class LiveA extends BaseA {\n"
            + "  public static void main(final String[] args) {\n"
            + "    if (\"outside\".equals(args[0])) {\n"
            + "      System.out.println(new closure.b.Middle());\n"
            + "    } else {\n"
            + "      System.out.println(new LiveA().base());\n"
            + "    }\n"
            + "  }\n"
            + "}\n");
    final Path classes = temporaryDirectory.resolve("subclass-classes");
    CompilationFixtureSupport.compile(
        classes,
        List.of(baseJava, liveJava),
        21,
        "-classpath",
        fixture.snapshot("b").filePath().toString());
    final Path jarA = fixture.snapshot("a").filePath();
    final Path rewrittenA = temporaryDirectory.resolve("a-subclass.jar");
    try (JarFile input = new JarFile(jarA.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(rewrittenA))) {
      for (final JarEntry entry : input.stream().toList()) {
        output.putNextEntry(outputEntry(entry));
        try (InputStream content = input.getInputStream(entry)) {
          content.transferTo(output);
        }
        output.closeEntry();
      }
      for (final String name : List.of("fixture/sub/BaseA.class", "fixture/sub/LiveA.class")) {
        output.putNextEntry(new JarEntry(name));
        Files.copy(classes.resolve(name), output);
        output.closeEntry();
      }
    }
    Files.move(rewrittenA, jarA, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

    final Path evidence = trace(temporaryDirectory, "fixture.sub.LiveA");
    final ServiceOperation operation = runtimeEvidenceOperation(fixture, List.of(evidence), true);
    final ElisionAnalysisModel.Analysis analysis = operation.service().finish(operation.prepared());
    final ArtifactTrimRecord recordA = recordFor(analysis.trimResult(), "a");
    final String javaBin = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    final Process usedProc =
        new ProcessBuilder(
                javaBin, "-cp", recordA.trimmedPath().toString(), "fixture.sub.LiveA", "used")
            .redirectErrorStream(true)
            .start();
    final String usedOut =
        new String(
            usedProc.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    final int usedExit = usedProc.waitFor();
    final Process outsideProc =
        new ProcessBuilder(
                javaBin, "-cp", recordA.trimmedPath().toString(), "fixture.sub.LiveA", "outside")
            .redirectErrorStream(true)
            .start();
    final String outsideOut =
        new String(
            outsideProc.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    final int outsideExit = outsideProc.waitFor();

    assertAll(
        "fresh JVM runs LiveA extends BaseA for traced path and fails linkage on omitted path",
        () -> assertThat(usedExit).isZero(),
        () -> assertThat(usedOut.trim()).isEqualTo("base"),
        () -> assertThat(outsideExit).isNotZero(),
        () -> assertThat(outsideOut).contains("NoClassDefFoundError").contains("closure/b/Middle"));
  }

  @Test
  void closedWorldTransformedArchiveRunsTracedMethodAndRetainsUncalledStructuralTypes()
      throws Exception {
    final Fixture fixture = fixtureWithLiveWorkload();
    final Path evidence = trace(temporaryDirectory, "fixture.live.LiveA");
    final ServiceOperation operation = runtimeEvidenceOperation(fixture, List.of(evidence), true);
    final ElisionAnalysisModel.Analysis analysis = operation.service().finish(operation.prepared());
    final TrimResult trimmed = analysis.trimResult();
    final ArtifactTrimRecord recordA = recordFor(trimmed, "a");
    final Set<String> retainedProviders =
        MavenArtifactPlan.prepare(fixture.mavenProject(), analysis).resolvedArtifacts().stream()
            .map(Artifact::getArtifactId)
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> archiveEntries = artifactEntries(trimmed, fixture, "a");

    assertAll(
        "closed-world output omits the body-only provider and retains structural linkage",
        () ->
            assertAll(
                "transformed archives omit jar-b and preserve frame/catch types",
                () -> assertThat(retainedProviders).doesNotContain("b"),
                () ->
                    assertThat(trimmed.records())
                        .extracting(record -> record.coordinate().artifactId())
                        .contains("a")
                        .doesNotContain("b"),
                () ->
                    assertThat(archiveEntries)
                        .contains(
                            "fixture/live/LiveA.class",
                            "fixture/live/FrameOnly.class",
                            "fixture/live/CatchOnly.class")
                        .doesNotContain("closure/b/Middle.class", "fixture/live/DeadA.class")),
        () -> assertTransformedRuntime(recordA));
  }

  @Test
  void closedWorldChangesMultiReleaseUpperTierProviderOutput() throws Exception {
    final Fixture fixture = fixtureWithRuntimeA(11);
    addUpperTierEntryReferencingLeaf(fixture, 17);
    final Path evidence = trace(temporaryDirectory, ENTRY);
    final OutputObservation conservative = output(fixture, evidence, false);
    final OutputObservation closedWorld = output(fixture, evidence, true);

    assertAll(
        "runtime evidence policy controls upper-tier MRJAR provider closure",
        () -> assertThat(conservative.retainedProviders()).contains("b", "c"),
        () -> assertThat(closedWorld.elidedProviders()).contains("b", "c"),
        () -> assertThat(conservative.generatedArtifacts()).contains("a"),
        () -> assertThat(closedWorld.generatedArtifacts()).contains("a"),
        () -> assertUpperTierEntry(conservative),
        () -> assertUpperTierEntry(closedWorld),
        () -> assertThat(conservative.middleEntries()).contains("closure/b/Middle.class"),
        () -> assertThat(closedWorld.middleEntries()).isEmpty());
  }

  private OutputObservation output(
      final Fixture fixture, final Path evidence, final boolean closedWorld)
      throws IOException, MojoFailureException {
    final ServiceOperation operation =
        runtimeEvidenceOperation(fixture, List.of(evidence), closedWorld);
    final ElisionAnalysisModel.Analysis analysis = operation.service().finish(operation.prepared());
    final TrimResult trimmed = analysis.trimResult();
    final ArtifactTrimRecord recordA = recordFor(trimmed, "a");
    final ElisionAnalysisModel.ApplyPlan plan =
        MavenArtifactPlan.prepare(fixture.mavenProject(), analysis);
    final Set<String> retainedProviders =
        plan.resolvedArtifacts().stream()
            .map(Artifact::getArtifactId)
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> allProviders =
        fixture.allSnapshots().stream()
            .map(snapshot -> snapshot.coordinate().artifactId())
            .collect(java.util.stream.Collectors.toSet());
    final Set<String> elidedProviders = new HashSet<>(allProviders);
    elidedProviders.removeAll(retainedProviders);
    final Set<String> middleEntries =
        retainedProviders.contains("b") ? artifactEntries(trimmed, fixture, "b") : Set.of();
    final boolean upperTierEntry =
        contains(recordA.trimmedPath(), "META-INF/versions/17/closure/a/Entry.class");
    return new OutputObservation(
        operation.prepared().policyOptions().runtimePolicy().allowedClasses(),
        retainedProviders,
        elidedProviders,
        trimmed.records().stream()
            .map(record -> record.coordinate().artifactId())
            .collect(java.util.stream.Collectors.toSet()),
        middleEntries,
        upperTierEntry);
  }

  private ServiceOperation runtimeEvidenceOperation(
      final Fixture fixture, final List<Path> evidence, final boolean closedWorld)
      throws IOException, MojoFailureException {
    return buildOperation(
        fixture,
        evidence,
        null,
        List.of(),
        true,
        List.of(),
        MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
        MavenPluginDescriptorFixtures.releasedProducerResolution(),
        closedWorld);
  }

  private Set<String> artifactEntries(
      final TrimResult result, final Fixture fixture, final String artifactId) throws IOException {
    final ArtifactTrimRecord record =
        result.records().stream()
            .filter(candidate -> candidate.coordinate().artifactId().equals(artifactId))
            .findFirst()
            .orElse(null);
    final Path finalPath =
        record == null ? fixture.snapshot(artifactId).filePath() : record.trimmedPath();
    try (JarFile archive = new JarFile(finalPath.toFile())) {
      return archive.stream().map(JarEntry::getName).collect(java.util.stream.Collectors.toSet());
    }
  }

  private static ArtifactTrimRecord recordFor(final TrimResult result, final String artifactId) {
    return result.records().stream()
        .filter(record -> record.coordinate().artifactId().equals(artifactId))
        .findFirst()
        .orElseThrow(() -> new AssertionError("No trim output for " + artifactId));
  }

  private static boolean contains(final Path archivePath, final String entryName)
      throws IOException {
    try (JarFile archive = new JarFile(archivePath.toFile())) {
      return archive.getEntry(entryName) != null;
    }
  }

  private static void assertUpperTierEntry(final OutputObservation observation) {
    final boolean upperTierEntryPresent = observation.upperTierEntry();
    assertThat(upperTierEntryPresent).isTrue();
  }

  private void addUpperTierEntryReferencingLeaf(final Fixture fixture, final int release)
      throws IOException {
    final Path sourceRoot =
        Files.createDirectories(temporaryDirectory.resolve("upper-tier-source"));
    final Path source = sourceRoot.resolve("closure/a/Entry.java");
    Files.createDirectories(source.getParent());
    Files.writeString(
        source,
        "package closure.a; public class Entry { "
            + "public Object make() { return new closure.c.Leaf(); } }\n");
    final Path classes = temporaryDirectory.resolve("upper-tier-classes");
    CompilationFixtureSupport.compile(
        classes,
        List.of(source),
        release,
        "-classpath",
        temporaryDirectory.resolve("classes").toString());
    final Path sourceJar = fixture.snapshot("a").filePath();
    final Path rewritten = temporaryDirectory.resolve("a-multi-release.jar");
    final Manifest manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().putValue("Multi-Release", "true");
    try (JarFile input = new JarFile(sourceJar.toFile());
        JarOutputStream output = new JarOutputStream(Files.newOutputStream(rewritten), manifest)) {
      for (final JarEntry entry : input.stream().toList()) {
        output.putNextEntry(outputEntry(entry));
        try (InputStream content = input.getInputStream(entry)) {
          content.transferTo(output);
        }
        output.closeEntry();
      }
      output.putNextEntry(new JarEntry("META-INF/versions/" + release + "/closure/a/Entry.class"));
      Files.copy(classes.resolve("closure/a/Entry.class"), output);
      output.closeEntry();
    }
    Files.move(rewritten, sourceJar, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
  }

  private static void assertTransformedRuntime(final ArtifactTrimRecord record)
      throws IOException, ReflectiveOperationException {
    try (URLClassLoader isolatedLoader =
        new URLClassLoader(new java.net.URL[] {record.trimmedPath().toUri().toURL()}, null)) {
      final Class<?> liveA = Class.forName("fixture.live.LiveA", true, isolatedLoader);
      assertAll(
          "isolated transformed archive supports traced use and rejects untraced use",
          () -> assertThat(liveA.getMethod("used").invoke(null)).isEqualTo("used"),
          () ->
              assertThatThrownBy(() -> liveA.getMethod("outside").invoke(null))
                  .isInstanceOf(InvocationTargetException.class)
                  .cause()
                  .isInstanceOf(NoClassDefFoundError.class)
                  .hasMessageContaining("closure/b/Middle"));
    }
  }

  private record OutputObservation(
      Set<String> allowedClasses,
      Set<String> retainedProviders,
      Set<String> elidedProviders,
      Set<String> generatedArtifacts,
      Set<String> middleEntries,
      boolean upperTierEntry) {}

  private static JarEntry outputEntry(final JarEntry inputEntry) {
    return new JarEntry(inputEntry.getName());
  }
}
