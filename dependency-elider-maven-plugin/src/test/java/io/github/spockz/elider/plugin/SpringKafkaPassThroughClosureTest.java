/* WHY: Exercises optional-link pass-through with the actual Spring Kafka archive. */

package io.github.spockz.elider.plugin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertAll;

import io.github.spockz.elider.model.ArtifactCoordinate;
import io.github.spockz.elider.model.ArtifactFileRef;
import io.github.spockz.elider.model.TraceData;
import io.github.spockz.elider.scanner.JarIndexScanner;
import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Verifies single-release closure with real optional Kafka Streams references. */
@SuppressWarnings({
  "PMD.AtLeastOneConstructor",
  "PMD.CommentRequired",
  "PMD.ExcessiveImports",
  "PMD.CouplingBetweenObjects",
  "PMD.AvoidDuplicateLiterals",
  "PMD.LawOfDemeter",
  "PMD.UseProperClassLoader"
})
final class SpringKafkaPassThroughClosureTest {
  private static final String LISTENER =
      "org/springframework/kafka/streams/KafkaStreamsMicrometerListener";
  private static final String STREAMS = "org/apache/kafka/streams/KafkaStreams";
  @TempDir private Path tempDir;

  @Test
  void actualSpringKafkaSupportsExplicitAndForcedUnchangedClosure() throws Exception {
    final Fixture fixture = fixture(false);
    final boolean[] descriptorReferencesStreams = {false};
    try (JarFile jar = new JarFile(fixture.springPath().toFile());
        java.io.InputStream bytes = jar.getInputStream(jar.getJarEntry(LISTENER + ".class"))) {
      new ClassReader(bytes)
          .accept(
              new ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(
                    final int access,
                    final String name,
                    final String descriptor,
                    final String signature,
                    final String[] exceptions) {
                  descriptorReferencesStreams[0] |= descriptor.contains("L" + STREAMS + ";");
                  return null;
                }
              },
              ClassReader.SKIP_CODE | ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
    }
    assertAll(
        () -> assertThat(descriptorReferencesStreams[0]).isTrue(),
        () -> assertThat(getClass().getClassLoader().getResource(STREAMS + ".class")).isNull(),
        () -> assertClosure(fixture.analyze(true), fixture),
        () -> assertClosure(fixture.analyze(false), fixture),
        () ->
            assertThat(fixture.analyze(false, false).reachableArtifacts())
                .contains(fixture.spring()));
  }

  @Test
  void transformedCandidateStillFailsOnMissingReference() throws Exception {
    final Fixture fixture = fixture(true);
    assertThatThrownBy(() -> fixture.analyze(false))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("candidate/Entry -> class missing/Required");
  }

  private static void assertClosure(final TrimAnalysisResult result, final Fixture fixture) {
    assertAll(
        () -> assertThat(result.candidateAnalyses()).doesNotContainKey(fixture.spring()),
        () -> {
          assertThat(result.candidateAnalyses()).containsKey(fixture.candidate());
          assertThat(result.candidateAnalyses().get(fixture.candidate()).retainedClasses())
              .contains("candidate/Entry", "candidate/Linked")
              .doesNotContain("candidate/Drop");
        });
  }

  private Fixture fixture(final boolean brokenCandidate)
      throws IOException, java.net.URISyntaxException {
    final URL listenerUrl = getClass().getClassLoader().getResource(LISTENER + ".class");
    if (listenerUrl == null
        || !(listenerUrl.openConnection() instanceof JarURLConnection jarConnection)) {
      throw new IOException("Spring Kafka test dependency is not available as a JAR");
    }
    final Path springPath = Path.of(jarConnection.getJarFileURL().toURI());
    final Artifact spring =
        artifact("org.springframework.kafka", "spring-kafka", "3.2.4", springPath);
    final Artifact bridge =
        artifact(
            "example",
            "bridge",
            "1.0",
            writeJar(
                "bridge",
                Map.of("bridge/Root", classBytes("bridge/Root", LISTENER, "candidate/Linked"))));
    final Artifact candidate =
        artifact(
            "example",
            "candidate",
            "1.0",
            writeJar(
                "candidate",
                Map.of(
                    "candidate/Entry",
                        classBytes(
                            "candidate/Entry", null, brokenCandidate ? "missing/Required" : null),
                    "candidate/Drop", classBytes("candidate/Drop", null, null),
                    "candidate/Linked", classBytes("candidate/Linked", null, null))));
    final List<ElisionAnalysisModel.ArtifactSnapshot> snapshots =
        MavenArtifactInventory.snapshots(List.of(bridge, spring, candidate));
    final List<ArtifactFileRef> refs = new ArrayList<>();
    for (final ElisionAnalysisModel.ArtifactSnapshot snapshot : snapshots) {
      refs.add(ArtifactFileRef.fromPath(snapshot.coordinate(), snapshot.filePath()));
    }
    final Map<Path, DependencyDynamicRoots.RootScan> scans =
        snapshots.stream()
            .collect(
                java.util.stream.Collectors.toMap(
                    ElisionAnalysisModel.ArtifactSnapshot::filePath,
                    snapshot -> new DependencyDynamicRoots.RootScan(Set.of(), true)));
    final MavenProject project = new MavenProject();
    project.setGroupId("example");
    project.setArtifactId("consumer");
    project.setVersion("1.0");
    project.setArtifacts(Set.of(bridge, spring, candidate));
    project.getProperties().setProperty("maven.compiler.release", "21");
    final Build build = new Build();
    build.setDirectory(tempDir.resolve("target").toString());
    project.setBuild(build);
    return new Fixture(
        project,
        snapshots,
        new TrimScanInputs(new JarIndexScanner().scan(refs), scans),
        springPath,
        coordinate("org.springframework.kafka", "spring-kafka", "3.2.4"),
        coordinate("example", "candidate", "1.0"));
  }

  private record Fixture(
      MavenProject project,
      List<ElisionAnalysisModel.ArtifactSnapshot> snapshots,
      TrimScanInputs scans,
      Path springPath,
      ArtifactCoordinate spring,
      ArtifactCoordinate candidate) {
    /* package */ TrimAnalysisResult analyze(final boolean explicit)
        throws IOException, MojoFailureException {
      return analyze(explicit, true);
    }

    /* package */ TrimAnalysisResult analyze(final boolean explicit, final boolean retainSpring)
        throws IOException, MojoFailureException {
      final Set<ArtifactCoordinate> retained =
          snapshots.stream()
              .map(ElisionAnalysisModel.ArtifactSnapshot::coordinate)
              .filter(coordinate -> retainSpring || !coordinate.equals(spring))
              .collect(java.util.stream.Collectors.toSet());
      final List<String> skips =
          explicit
              ? List.of(
                  "example:bridge:1.0:jar:", "org.springframework.kafka:spring-kafka:3.2.4:jar:")
              : List.of("example:bridge:1.0:jar:");
      final TrimRequest request =
          new TrimRequest(
              project,
              null,
              snapshots,
              scans,
              retained,
              new TrimEvidence(
                  TraceData.of(Set.of("candidate.Entry")), Set.of(), Set.of(), Set.of()),
              new TrimPolicy(
                  List.of(),
                  false,
                  skips,
                  false,
                  MavenDependencyTrimmer.MRJAR_VERTICAL_SHADING,
                  true,
                  true,
                  MavenDependencyTrimmer.DEFAULT_TRIM_WORKERS,
                  DuplicateClassPolicy.NONE));
      return MavenDependencyTrimmer.analyzeInMemory(
          request, Map.of(), explicit || !retainSpring ? Set.of() : Set.of(spring));
    }
  }

  private static Artifact artifact(
      final String group, final String name, final String version, final Path path) {
    final Artifact artifact =
        new DefaultArtifact(
            group, name, version, "runtime", "jar", null, new DefaultArtifactHandler("jar"));
    artifact.setFile(path.toFile());
    return artifact;
  }

  private static ArtifactCoordinate coordinate(
      final String group, final String name, final String version) {
    return new ArtifactCoordinate(group, name, version, "jar", "", "runtime");
  }

  @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
  private Path writeJar(final String name, final Map<String, byte[]> classes) throws IOException {
    final Path path = tempDir.resolve(name + ".jar");
    try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(path))) {
      for (final Map.Entry<String, byte[]> entry : classes.entrySet()) {
        output.putNextEntry(new JarEntry(entry.getKey() + ".class"));
        output.write(entry.getValue());
        output.closeEntry();
      }
    }
    return path;
  }

  private static byte[] classBytes(
      final String name, final String reference, final String fieldType) {
    final ClassWriter writer = new ClassWriter(0);
    writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, name, null, "java/lang/Object", null);
    if (fieldType != null) {
      writer
          .visitField(Opcodes.ACC_PUBLIC, "missing", "L" + fieldType + ";", null, null)
          .visitEnd();
    }
    if (reference != null) {
      final MethodVisitor method =
          writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "use", "()V", null, null);
      method.visitCode();
      method.visitTypeInsn(Opcodes.NEW, reference);
      method.visitInsn(Opcodes.POP);
      method.visitInsn(Opcodes.RETURN);
      method.visitMaxs(1, 0);
      method.visitEnd();
    }
    writer.visitEnd();
    return writer.toByteArray();
  }
}
